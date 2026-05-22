package server

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/gologger"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"golang.org/x/net/http/httpguts"
)

// HTTPServer is a http server instance that listens both
// TLS and Non-TLS based servers.
type HTTPServer struct {
	options         *Options
	tlsserver       http.Server
	nontlsserver    http.Server
	customBanner    string
	defaultResponse string
	staticHandler   http.Handler
}

const (
	b64BodyPrefix       = "/b64_body:"
	maxRequestBodyBytes = 1 << 20
	maxHeaderBytes      = 1 << 20
	readTimeout         = 30 * time.Second
	readHeaderTimeout   = 10 * time.Second
	writeTimeout        = 30 * time.Second
	idleTimeout         = 60 * time.Second
	maxDynamicDelay     = 30 * time.Second
)

type noopLogger struct {
}

func (l *noopLogger) Write(p []byte) (n int, err error) {
	return 0, nil
}

// disableDirectoryListing disables directory listing on http.FileServer
func disableDirectoryListing(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") || r.URL.Path == "" {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// NewHTTPServer returns a new TLS & Non-TLS HTTP server.
func NewHTTPServer(options *Options) (*HTTPServer, error) {
	server := &HTTPServer{options: options}

	// If a static directory is specified, also serve it.
	if options.HTTPDirectory != "" {
		abs, err := filepath.Abs(options.HTTPDirectory)
		if err != nil {
			gologger.Warning().Msgf("Could not resolve HTTP directory path: %s", err)
			abs = options.HTTPDirectory
		}
		gologger.Info().Msgf("Loading directory (%s) to serve from : %s/s/", abs, strings.Join(options.Domains, ","))
		server.staticHandler = http.StripPrefix("/s/", disableDirectoryListing(http.FileServer(http.Dir(options.HTTPDirectory))))
	}
	// If custom index, read the custom index file and serve it.
	// Supports {DOMAIN} placeholders.
	if options.HTTPIndex != "" {
		abs, err := filepath.Abs(options.HTTPIndex)
		if err != nil {
			gologger.Warning().Msgf("Could not resolve HTTP index path: %s", err)
			abs = options.HTTPIndex
		}
		gologger.Info().Msgf("Using custom server index: %s", abs)
		if data, err := os.ReadFile(options.HTTPIndex); err == nil {
			server.customBanner = string(data)
		}
	}
	// If default response file is specified, read it and serve for all requests.
	// This takes priority over all other response options.
	// Supports {DOMAIN} placeholders.
	if options.DefaultHTTPResponseFile != "" {
		abs, err := filepath.Abs(options.DefaultHTTPResponseFile)
		if err != nil {
			gologger.Warning().Msgf("Could not resolve default HTTP response file path: %s", err)
			abs = options.DefaultHTTPResponseFile
		}
		gologger.Info().Msgf("Using default HTTP response file for all requests: %s", abs)
		if data, err := os.ReadFile(options.DefaultHTTPResponseFile); err == nil {
			server.defaultResponse = string(data)
		}
	}
	router := &http.ServeMux{}
	router.Handle("/", server.logger(server.corsMiddleware(http.HandlerFunc(server.defaultHandler))))
	router.Handle("/register", server.corsMiddleware(server.authMiddleware(http.HandlerFunc(server.registerHandler))))
	router.Handle("/deregister", server.corsMiddleware(server.authMiddleware(http.HandlerFunc(server.deregisterHandler))))
	router.Handle("/poll", server.corsMiddleware(server.authMiddleware(http.HandlerFunc(server.pollHandler))))
	if server.options.EnableMetrics {
		router.Handle("/metrics", server.corsMiddleware(server.authMiddleware(http.HandlerFunc(server.metricsHandler))))
	}
	server.tlsserver = http.Server{
		Addr:              formatAddress(options.ListenIP, options.HttpsPort),
		Handler:           router,
		ErrorLog:          log.New(&noopLogger{}, "", 0),
		ReadTimeout:       readTimeout,
		ReadHeaderTimeout: readHeaderTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
	server.nontlsserver = http.Server{
		Addr:              formatAddress(options.ListenIP, options.HttpPort),
		Handler:           router,
		ErrorLog:          log.New(&noopLogger{}, "", 0),
		ReadTimeout:       readTimeout,
		ReadHeaderTimeout: readHeaderTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
	return server, nil
}

// ListenAndServe listens on http and/or https ports for the server.
func (h *HTTPServer) ListenAndServe(tlsConfig *tls.Config, httpAlive, httpsAlive chan bool) {
	go func() {
		if tlsConfig == nil {
			return
		}
		h.tlsserver.TLSConfig = tlsConfig

		httpsAlive <- true
		if err := h.tlsserver.ListenAndServeTLS("", ""); err != nil {
			gologger.Error().Msgf("Could not serve http on tls: %s\n", err)
			httpsAlive <- false
		}
	}()

	httpAlive <- true
	if err := h.nontlsserver.ListenAndServe(); err != nil {
		httpAlive <- false
		gologger.Error().Msgf("Could not serve http: %s\n", err)
	}
}

// Close gracefully shuts down both the TLS and non-TLS HTTP servers, waiting
// up to the given timeout for active connections to finish before forcibly
// closing them.
func (h *HTTPServer) Close(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return errors.Join(
		h.nontlsserver.Shutdown(ctx),
		h.tlsserver.Shutdown(ctx),
	)
}

func (h *HTTPServer) logger(handler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req, _ := httputil.DumpRequest(r, true)
		reqString := string(req)

		gologger.Debug().Msgf("New HTTP request: \n\n%s\n", reqString)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)

		resp, _ := httputil.DumpResponse(rec.Result(), true)
		respString := string(resp)

		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		data := rec.Body.Bytes()

		w.WriteHeader(rec.Result().StatusCode)
		_, _ = w.Write(data)

		var host string
		// Check if the client's ip should be taken from a custom header (eg reverse proxy)
		if originIP := r.Header.Get(h.options.OriginIPHeader); originIP != "" {
			host = originIP
		} else {
			host, _, _ = net.SplitHostPort(r.RemoteAddr)
		}

		// if root-tld is enabled stores any interaction towards the main domain
		if h.options.RootTLD {
			for _, domain := range h.options.Domains {
				if h.options.RootTLD && stringsutil.HasSuffixI(r.Host, domain) {
					ID := domain
					host, _, _ := net.SplitHostPort(r.RemoteAddr)
					interaction := &Interaction{
						Protocol:      httpProtocol(r),
						UniqueID:      r.Host,
						FullId:        r.Host,
						RawRequest:    reqString,
						RawResponse:   respString,
						RemoteAddress: host,
						Timestamp:     time.Now(),
					}
					data, err := jsoniter.Marshal(interaction)
					if err != nil {
						gologger.Warning().Msgf("Could not encode root tld http interaction: %s\n", err)
					} else {
						gologger.Debug().Msgf("Root TLD HTTP Interaction: \n%s\n", string(data))
						if err := h.options.Storage.AddInteractionWithId(ID, data); err != nil {
							gologger.Warning().Msgf("Could not store root tld http interaction: %s\n", err)
						}
					}
				}
			}
		}

		if h.options.ScanEverywhere {
			chunks := stringsutil.SplitAny(reqString, ".\n\t\"'")
			for _, chunk := range chunks {
				for part := range stringsutil.SlideWithLength(chunk, h.options.GetIdLength()) {
					normalizedPart := strings.ToLower(part)
					if h.options.isCorrelationID(normalizedPart) {
						h.handleInteraction(r, normalizedPart, part, reqString, respString, host)
					}
				}
			}
		} else {
			parts := strings.Split(r.Host, ".")
			for i, part := range parts {
				for partChunk := range stringsutil.SlideWithLength(part, h.options.GetIdLength()) {
					normalizedPartChunk := strings.ToLower(partChunk)
					if h.options.isCorrelationID(normalizedPartChunk) {
						fullID := part
						if i+1 <= len(parts) {
							fullID = strings.Join(parts[:i+1], ".")
						}
						h.handleInteraction(r, normalizedPartChunk, fullID, reqString, respString, host)
					}
				}
			}
		}
	}
}

func httpProtocol(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func (h *HTTPServer) handleInteraction(r *http.Request, uniqueID, fullID, reqString, respString, hostPort string) {
	correlationID := uniqueID[:h.options.CorrelationIdLength]

	interaction := &Interaction{
		Protocol:      httpProtocol(r),
		UniqueID:      uniqueID,
		FullId:        fullID,
		RawRequest:    reqString,
		RawResponse:   respString,
		RemoteAddress: hostPort,
		Timestamp:     time.Now(),
	}
	data, err := jsoniter.Marshal(interaction)
	if err != nil {
		gologger.Warning().Msgf("Could not encode http interaction: %s\n", err)
	} else {
		gologger.Debug().Msgf("HTTP Interaction: \n%s\n", string(data))

		if err := h.options.Storage.AddInteraction(correlationID, data); err != nil {
			gologger.Warning().Msgf("Could not store http interaction: %s\n", err)
		}
	}
}

const banner = `<h1> Interactsh Server </h1>

<a href='https://github.com/projectdiscovery/interactsh'><b>Interactsh</b></a> is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions.<br><br>

If you notice any interactions from <b>*.%s</b> in your logs, it's possible that someone (internal security engineers, pen-testers, bug-bounty hunters) has been testing your application.<br><br>

You should investigate the sites where these interactions were generated from, and if a vulnerability exists, examine the root cause and take the necessary steps to mitigate the issue.
`

func extractServerDomain(h *HTTPServer, req *http.Request) string {
	if h.options.HeaderServer != "" {
		return h.options.HeaderServer
	}

	var domain string
	// use first domain as default (todo: should be extracted from certificate)
	if len(h.options.Domains) > 0 {
		// attempts to extract the domain name from host header
		for _, configuredDomain := range h.options.Domains {
			if stringsutil.HasSuffixI(req.Host, configuredDomain) {
				domain = configuredDomain
				break
			}
		}
		// fallback to first domain in case of unknown host header
		if domain == "" {
			domain = h.options.Domains[0]
		}
	}
	return domain
}

// defaultHandler is a handler for default collaborator requests
func (h *HTTPServer) defaultHandler(w http.ResponseWriter, req *http.Request) {
	atomic.AddUint64(&h.options.Stats.Http, 1)

	domain := extractServerDomain(h, req)
	w.Header().Set("Server", domain)
	if !h.options.NoVersionHeader {
		w.Header().Set("X-Interactsh-Version", h.options.Version)
	}

	reflection := h.options.URLReflection(req.Host)

	// If default response is set, serve it for all requests (highest priority)
	if h.defaultResponse != "" {
		_, _ = fmt.Fprint(w, strings.ReplaceAll(h.defaultResponse, "{DOMAIN}", domain))
		return
	}

	if stringsutil.HasPrefixI(req.URL.Path, "/s/") && h.staticHandler != nil {
		if h.options.DynamicResp && len(req.URL.Query()) > 0 {
			values := req.URL.Query()
			applyDynamicHeaders(w, values["header"])
			ensureDynamicDefaults(w)
			if delay, ok := parseDynamicDelay(values.Get("delay")); ok {
				time.Sleep(delay)
			}
			if status, ok := parseDynamicStatus(values.Get("status")); ok {
				w.WriteHeader(status)
			}
		}
		h.staticHandler.ServeHTTP(w, req)
	} else if req.URL.Path == "/" && reflection == "" {
		if h.customBanner != "" {
			_, _ = fmt.Fprint(w, strings.ReplaceAll(h.customBanner, "{DOMAIN}", domain))
		} else {
			_, _ = fmt.Fprintf(w, banner, domain)
		}
	} else if strings.EqualFold(req.URL.Path, "/robots.txt") {
		_, _ = fmt.Fprintf(w, "User-agent: *\nDisallow: / # %s", reflection)
	} else if stringsutil.HasSuffixI(req.URL.Path, ".json") {
		_, _ = fmt.Fprintf(w, "{\"data\":\"%s\"}", reflection)
		w.Header().Set("Content-Type", "application/json")
	} else if stringsutil.HasSuffixI(req.URL.Path, ".xml") {
		_, _ = fmt.Fprintf(w, "<data>%s</data>", reflection)
		w.Header().Set("Content-Type", "application/xml")
	} else {
		if h.options.DynamicResp && (len(req.URL.Query()) > 0 || stringsutil.HasPrefixI(req.URL.Path, "/b64_body:")) {
			writeResponseFromDynamicRequest(w, req)
			return
		}
		_, _ = fmt.Fprintf(w, "<html><head></head><body>%s</body></html>", reflection)
	}
}

// writeResponseFromDynamicRequest writes a response to http.ResponseWriter
// based on dynamic data from HTTP URL Query parameters.
//
// The following parameters are supported -
//
//	body (response body)
//	header (response header)
//	status (response status code)
//	delay (response time)
func writeResponseFromDynamicRequest(w http.ResponseWriter, req *http.Request) {
	values := req.URL.Query()

	var pathBody []byte
	if encoded := extractB64BodyFromPath(req.URL.Path); encoded != "" {
		if decodedBytes, err := base64.StdEncoding.DecodeString(encoded); err == nil {
			pathBody = decodedBytes
		}
	}
	applyDynamicHeaders(w, values["header"])
	ensureDynamicDefaults(w)
	if delay, ok := parseDynamicDelay(values.Get("delay")); ok {
		time.Sleep(delay)
	}
	if status, ok := parseDynamicStatus(values.Get("status")); ok {
		w.WriteHeader(status)
	}
	if len(pathBody) > 0 {
		_, _ = w.Write(pathBody)
	}
	if body := values.Get("body"); body != "" {
		_, _ = w.Write([]byte(body))
	}
	if b64Body := values.Get("b64_body"); b64Body != "" {
		if decodedBytes, err := base64.StdEncoding.DecodeString(b64Body); err == nil {
			_, _ = w.Write(decodedBytes)
		}
	}
}

func extractB64BodyFromPath(path string) string {
	if !stringsutil.HasPrefixI(path, b64BodyPrefix) {
		return ""
	}
	start := len(b64BodyPrefix)
	if start >= len(path) {
		return ""
	}
	end := strings.Index(path[start:], "/")
	if end == -1 {
		end = len(path)
	} else {
		end += start
	}
	if start >= end {
		return ""
	}
	return path[start:end]
}

func applyDynamicHeaders(w http.ResponseWriter, headers []string) {
	for _, header := range headers {
		name, value, ok := parseDynamicHeader(header)
		if !ok {
			continue
		}
		w.Header().Add(name, value)
	}
}

func ensureDynamicDefaults(w http.ResponseWriter) {
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	if w.Header().Get("X-Content-Type-Options") == "" {
		w.Header().Set("X-Content-Type-Options", "nosniff")
	}
}

func parseDynamicHeader(header string) (string, string, bool) {
	headerParts := strings.SplitN(header, ":", 2)
	if len(headerParts) != 2 {
		return "", "", false
	}
	name := strings.TrimSpace(headerParts[0])
	value := strings.TrimSpace(headerParts[1])
	if !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(value) {
		return "", "", false
	}
	return name, value, true
}

func parseDynamicDelay(delay string) (time.Duration, bool) {
	if delay == "" {
		return 0, false
	}
	parsed, err := strconv.Atoi(delay)
	if err != nil || parsed <= 0 {
		return 0, false
	}
	if parsed > int(maxDynamicDelay.Seconds()) {
		parsed = int(maxDynamicDelay.Seconds())
	}
	return time.Duration(parsed) * time.Second, true
}

func parseDynamicStatus(status string) (int, bool) {
	if status == "" {
		return 0, false
	}
	parsed, err := strconv.Atoi(status)
	if err != nil || parsed < 100 || parsed > 599 {
		return 0, false
	}
	return parsed, true
}

// RegisterRequest is a request for client registration to interactsh server.
type RegisterRequest struct {
	// PublicKey is the public RSA Key of the client.
	PublicKey string `json:"public-key"`
	// SecretKey is the secret-key for correlation ID registered for the client.
	SecretKey string `json:"secret-key"`
	// CorrelationID is an ID for correlation with requests.
	CorrelationID string `json:"correlation-id"`
}

// registerHandler is a handler for client register requests
func (h *HTTPServer) registerHandler(w http.ResponseWriter, req *http.Request) {
	r := &RegisterRequest{}
	if err := decodeJSONBody(w, req, r); err != nil {
		if isRequestBodyTooLarge(err) {
			jsonError(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		gologger.Warning().Msgf("Could not decode json body: %s\n", err)
		jsonError(w, fmt.Sprintf("could not decode json body: %s", err), http.StatusBadRequest)
		return
	}

	atomic.AddInt64(&h.options.Stats.Sessions, 1)

	if err := h.options.Storage.SetIDPublicKey(r.CorrelationID, r.SecretKey, r.PublicKey); err != nil {
		gologger.Warning().Msgf("Could not set id and public key for %s: %s\n", r.CorrelationID, err)
		jsonError(w, fmt.Sprintf("could not set id and public key: %s", err), http.StatusBadRequest)
		return
	}
	jsonMsg(w, "registration successful", http.StatusOK)
	gologger.Debug().Msgf("Registered correlationID %s for key\n", r.CorrelationID)
}

// DeregisterRequest is a request for client deregistration to interactsh server.
type DeregisterRequest struct {
	// CorrelationID is an ID for correlation with requests.
	CorrelationID string `json:"correlation-id"`
	// SecretKey is the secretKey for the interactsh client.
	SecretKey string `json:"secret-key"`
}

// deregisterHandler is a handler for client deregister requests
func (h *HTTPServer) deregisterHandler(w http.ResponseWriter, req *http.Request) {
	atomic.AddInt64(&h.options.Stats.Sessions, -1)

	r := &DeregisterRequest{}
	if err := decodeJSONBody(w, req, r); err != nil {
		if isRequestBodyTooLarge(err) {
			jsonError(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		gologger.Warning().Msgf("Could not decode json body: %s\n", err)
		jsonError(w, fmt.Sprintf("could not decode json body: %s", err), http.StatusBadRequest)
		return
	}

	if err := h.options.Storage.RemoveID(r.CorrelationID, r.SecretKey); err != nil {
		gologger.Warning().Msgf("Could not remove id for %s: %s\n", r.CorrelationID, err)
		jsonError(w, fmt.Sprintf("could not remove id: %s", err), http.StatusBadRequest)
		return
	}
	if h.options.RootTLD {
		for _, domain := range h.options.Domains {
			_ = h.options.Storage.RemoveConsumer(domain, r.CorrelationID)
		}
	}
	if h.options.Token != "" {
		_ = h.options.Storage.RemoveConsumer(h.options.Token, r.CorrelationID)
	}
	jsonMsg(w, "deregistration successful", http.StatusOK)
	gologger.Debug().Msgf("Deregistered correlationID %s for key\n", r.CorrelationID)
}

// PollResponse is the response for a polling request
type PollResponse struct {
	Data    []string `json:"data"`
	Extra   []string `json:"extra"`
	AESKey  string   `json:"aes_key"`
	TLDData []string `json:"tlddata,omitempty"`
}

// pollHandler is a handler for client poll requests
func (h *HTTPServer) pollHandler(w http.ResponseWriter, req *http.Request) {
	ID := req.URL.Query().Get("id")
	if ID == "" {
		jsonError(w, "no id specified for poll", http.StatusBadRequest)
		return
	}
	secret := req.URL.Query().Get("secret")
	if secret == "" {
		jsonError(w, "no secret specified for poll", http.StatusBadRequest)
		return
	}

	data, aesKey, err := h.options.Storage.GetInteractions(ID, secret)
	if err != nil {
		gologger.Warning().Msgf("Could not get interactions for %s: %s\n", ID, err)
		jsonError(w, fmt.Sprintf("could not get interactions: %s", err), http.StatusBadRequest)
		return
	}

	// At this point the client is authenticated, so we return also the data related to the auth token
	var tlddata, extradata []string
	if h.options.RootTLD {
		for _, domain := range h.options.Domains {
			interactions, _ := h.options.Storage.GetInteractionsWithIdForConsumer(domain, ID)
			// root domains interaction are not encrypted
			tlddata = append(tlddata, interactions...)
		}
	}
	if h.options.Token != "" {
		// auth token interactions are not encrypted
		extradata, _ = h.options.Storage.GetInteractionsWithIdForConsumer(h.options.Token, ID)
	}
	response := &PollResponse{Data: data, AESKey: aesKey, TLDData: tlddata, Extra: extradata}

	if err := jsoniter.NewEncoder(w).Encode(response); err != nil {
		gologger.Warning().Msgf("Could not encode interactions for %s: %s\n", ID, err)
		jsonError(w, fmt.Sprintf("could not encode interactions: %s", err), http.StatusBadRequest)
		return
	}
	gologger.Debug().Msgf("Polled %d interactions for %s correlationID\n", len(data), ID)
}

func (h *HTTPServer) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Set CORS headers for the preflight request
		if req.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", h.options.OriginURL)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", h.options.OriginURL)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		next.ServeHTTP(w, req)
	})
}

func jsonBody(w http.ResponseWriter, key, value string, code int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_ = jsoniter.NewEncoder(w).Encode(map[string]interface{}{key: value})
}

func jsonError(w http.ResponseWriter, err string, code int) {
	jsonBody(w, "error", err, code)
}

func jsonMsg(w http.ResponseWriter, err string, code int) {
	jsonBody(w, "message", err, code)
}

func decodeJSONBody(w http.ResponseWriter, req *http.Request, target interface{}) error {
	req.Body = http.MaxBytesReader(w, req.Body, maxRequestBodyBytes)
	decoder := jsoniter.NewDecoder(req.Body)
	return decoder.Decode(target)
}

func isRequestBodyTooLarge(err error) bool {
	var maxBytesErr *http.MaxBytesError
	return errors.As(err, &maxBytesErr)
}

func (h *HTTPServer) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !h.checkToken(req) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, req)
	})
}

func (h *HTTPServer) checkToken(req *http.Request) bool {
	if !h.options.Auth {
		return true
	}
	provided := req.Header.Get("Authorization")
	if provided == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(h.options.Token), []byte(provided)) == 1
}

// metricsHandler is a handler for /metrics endpoint
func (h *HTTPServer) metricsHandler(w http.ResponseWriter, req *http.Request) {
	interactMetrics := h.options.Stats
	interactMetrics.Cache = GetCacheMetrics(h.options)
	interactMetrics.Cpu = GetCpuMetrics()
	interactMetrics.Memory = GetMemoryMetrics()
	interactMetrics.Network = GetNetworkMetrics()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = jsoniter.NewEncoder(w).Encode(interactMetrics)
}
