package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"mirror-registry/internal/config"

	"github.com/rs/zerolog"
)

// Handler handles HTTP requests
type Handler struct {
	config *config.Config
	logger zerolog.Logger
	client *http.Client
}

// New creates a new handler
func New(cfg *config.Config, logger zerolog.Logger) *Handler {
	return &Handler{
		config: cfg,
		logger: logger,
		client: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// Don't follow redirects automatically
				return http.ErrUseLastResponse
			},
		},
	}
}

// getClientIP extracts the client IP address from the request
func (h *Handler) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Fallback to RemoteAddr
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}

// getBearerToken fetches a Bearer token from the token service endpoint
// This implements Docker Registry v2 OAuth2 token authentication
func (h *Handler) getBearerToken(realm, service, scope string, username, password string, customHeaders map[string]string) (string, error) {
	tokenURL := realm
	if service != "" || scope != "" {
		u, err := url.Parse(realm)
		if err != nil {
			return "", fmt.Errorf("invalid realm URL: %w", err)
		}
		q := u.Query()
		if service != "" {
			q.Set("service", service)
		}
		if scope != "" {
			q.Set("scope", scope)
		}
		u.RawQuery = q.Encode()
		tokenURL = u.String()
	}

	h.logger.Debug().
		Str("token_url", tokenURL).
		Str("service", service).
		Str("scope", scope).
		Msg("Fetching Bearer token from token service")

	req, err := http.NewRequest("GET", tokenURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}

	if username != "" && password != "" {
		req.SetBasicAuth(username, password)
	}

	// Add custom headers
	for k, v := range customHeaders {
		req.Header.Set(k, v)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token service returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var tokenResponse struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"` // Some registries use this field
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}

	token := tokenResponse.Token
	if token == "" {
		token = tokenResponse.AccessToken
	}

	if token == "" {
		return "", fmt.Errorf("token response did not contain a token")
	}

	h.logger.Debug().
		Str("token_url", tokenURL).
		Msg("Successfully fetched Bearer token")

	return token, nil
}

// parseWwwAuthenticate parses the Www-Authenticate header to extract realm, service, and scope
func parseWwwAuthenticate(wwwAuth string) (realm, service, scope string) {
	// Format: Bearer realm="...",service="...",scope="..."
	if !strings.HasPrefix(strings.ToLower(wwwAuth), "bearer ") {
		return "", "", ""
	}

	parts := strings.Split(wwwAuth[len("bearer "):], ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "realm=") {
			realm = strings.Trim(part[len("realm="):], "\"")
		} else if strings.HasPrefix(part, "service=") {
			service = strings.Trim(part[len("service="):], "\"")
		} else if strings.HasPrefix(part, "scope=") {
			scope = strings.Trim(part[len("scope="):], "\"")
		}
	}

	return realm, service, scope
}

// logRequestStart logs the start of a request
func (h *Handler) logRequestStart(r *http.Request, handlerName string) {
	h.logger.Info().
		Str("handler", handlerName).
		Str("method", r.Method).
		Str("path", r.URL.Path).
		Str("query", r.URL.RawQuery).
		Str("client_ip", h.getClientIP(r)).
		Str("user_agent", r.Header.Get("User-Agent")).
		Msg("Request started")
}

// HandleV2 handles the /v2/ endpoint for API version detection
func (h *Handler) HandleV2(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	h.logRequestStart(r, "HandleV2")

	w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("{}"))

	h.logger.Info().
		Str("handler", "HandleV2").
		Str("path", r.URL.Path).
		Int("status", http.StatusOK).
		Dur("duration_ms", time.Since(startTime)).
		Msg("Request completed")
}

// HandleHealth handles health check requests
func (h *Handler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	h.logRequestStart(r, "HandleHealth")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"healthy"}`))

	h.logger.Info().
		Str("handler", "HandleHealth").
		Str("path", r.URL.Path).
		Int("status", http.StatusOK).
		Dur("duration_ms", time.Since(startTime)).
		Msg("Request completed")
}

// HandleRoot handles root path requests
func (h *Handler) HandleRoot(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	h.logRequestStart(r, "HandleRoot")

	// Docker Registry API v2 doesn't require root path, but we return a simple response
	w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("{}"))

	h.logger.Info().
		Str("handler", "HandleRoot").
		Str("path", r.URL.Path).
		Int("status", http.StatusOK).
		Dur("duration_ms", time.Since(startTime)).
		Msg("Request completed")
}

// HandleNotFound handles 404 errors with Docker Registry API format
func (h *Handler) HandleNotFound(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	h.logger.Warn().
		Str("handler", "HandleNotFound").
		Str("method", r.Method).
		Str("path", r.URL.Path).
		Str("query", r.URL.RawQuery).
		Str("client_ip", h.getClientIP(r)).
		Str("user_agent", r.Header.Get("User-Agent")).
		Msg("404 Not Found")

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte(`{"errors":[{"code":"NAME_UNKNOWN","message":"repository name not known to registry"}]}`))

	h.logger.Info().
		Str("handler", "HandleNotFound").
		Str("path", r.URL.Path).
		Int("status", http.StatusNotFound).
		Dur("duration_ms", time.Since(startTime)).
		Msg("Request completed")
}

// writeErrorResponse writes a Docker Registry API v2 compliant error response
func (h *Handler) writeErrorResponse(w http.ResponseWriter, code, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
	w.WriteHeader(statusCode)

	errorResponse := struct {
		Errors []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}{
		Errors: []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}{
			{Code: code, Message: message},
		},
	}

	json.NewEncoder(w).Encode(errorResponse)
}

// HandleManifest handles manifest requests with fallback logic
func (h *Handler) HandleManifest(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	h.logRequestStart(r, "HandleManifest")

	// Parse path manually to support image names with slashes
	// Path format: /v2/{name}/manifests/{reference}
	path := strings.TrimPrefix(r.URL.Path, "/v2/")
	h.logger.Debug().
		Str("raw_path", r.URL.Path).
		Str("parsed_path", path).
		Msg("Parsing manifest path")

	parts := strings.SplitN(path, "/manifests/", 2)
	if len(parts) != 2 {
		h.logger.Warn().
			Str("path", r.URL.Path).
			Str("parsed_path", path).
			Msg("Invalid manifest path format")
		http.Error(w, "NAME_INVALID", http.StatusBadRequest)
		h.logger.Info().
			Str("handler", "HandleManifest").
			Str("path", r.URL.Path).
			Int("status", http.StatusBadRequest).
			Dur("duration_ms", time.Since(startTime)).
			Msg("Request completed with error")
		return
	}

	name := parts[0]
	reference := parts[1]

	h.logger.Info().
		Str("name", name).
		Str("reference", reference).
		Str("client_ip", h.getClientIP(r)).
		Msg("Processing manifest request")

	// Try hot registry first
	h.logger.Debug().
		Str("backend", "hot").
		Str("backend_url", h.config.Registry.Hot.URL).
		Str("name", name).
		Str("reference", reference).
		Msg("Attempting to fetch manifest from hot registry")

	if h.proxyManifest(w, r, &h.config.Registry.Hot, name, reference) {
		h.logger.Info().
			Str("handler", "HandleManifest").
			Str("name", name).
			Str("reference", reference).
			Str("backend", "hot").
			Int("status", http.StatusOK).
			Dur("duration_ms", time.Since(startTime)).
			Msg("Request completed successfully")
		return
	}

	// Fallback to cold registry
	h.logger.Debug().
		Str("backend", "cold").
		Str("backend_url", h.config.Registry.Cold.URL).
		Str("name", name).
		Str("reference", reference).
		Msg("Attempting to fetch manifest from cold registry")

	if h.proxyManifest(w, r, &h.config.Registry.Cold, name, reference) {
		h.logger.Info().
			Str("handler", "HandleManifest").
			Str("name", name).
			Str("reference", reference).
			Str("backend", "cold").
			Int("status", http.StatusOK).
			Dur("duration_ms", time.Since(startTime)).
			Msg("Request completed successfully")
		return
	}

	// Not found in either registry
	h.logger.Warn().
		Str("name", name).
		Str("reference", reference).
		Str("client_ip", h.getClientIP(r)).
		Msg("Manifest not found in any registry")
	h.writeErrorResponse(w, "MANIFEST_UNKNOWN", "manifest unknown", http.StatusNotFound)

	h.logger.Info().
		Str("handler", "HandleManifest").
		Str("name", name).
		Str("reference", reference).
		Int("status", http.StatusNotFound).
		Dur("duration_ms", time.Since(startTime)).
		Msg("Request completed with not found")
}

// HandleBlob handles blob requests by redirecting to the backend with 307.
// All blob requests are redirected to the backend (hot or cold), and the Docker client
// will use its local credentials (from docker login) to authenticate with the backend.
func (h *Handler) HandleBlob(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	h.logRequestStart(r, "HandleBlob")

	// Parse path manually to support image names with slashes
	// Path format: /v2/{name}/blobs/{digest}
	path := strings.TrimPrefix(r.URL.Path, "/v2/")
	h.logger.Debug().
		Str("raw_path", r.URL.Path).
		Str("parsed_path", path).
		Msg("Parsing blob path")

	parts := strings.SplitN(path, "/blobs/", 2)
	if len(parts) != 2 {
		h.logger.Warn().
			Str("path", r.URL.Path).
			Str("parsed_path", path).
			Msg("Invalid blob path format")
		h.writeErrorResponse(w, "NAME_INVALID", "invalid repository name", http.StatusBadRequest)
		h.logger.Info().
			Str("handler", "HandleBlob").
			Str("path", r.URL.Path).
			Int("status", http.StatusBadRequest).
			Dur("duration_ms", time.Since(startTime)).
			Msg("Request completed with error")
		return
	}

	name := parts[0]
	digest := parts[1]

	h.logger.Info().
		Str("name", name).
		Str("digest", digest).
		Str("client_ip", h.getClientIP(r)).
		Msg("Processing blob request")

	// Try hot registry first
	h.logger.Debug().
		Str("backend", "hot").
		Str("backend_url", h.config.Registry.Hot.URL).
		Str("name", name).
		Str("digest", digest).
		Msg("Attempting to check blob in hot registry")

	if h.handleBlobRequest(w, r, &h.config.Registry.Hot, name, digest) {
		h.logger.Info().
			Str("handler", "HandleBlob").
			Str("name", name).
			Str("digest", digest).
			Str("backend", "hot").
			Dur("duration_ms", time.Since(startTime)).
			Msg("Request completed")
		return
	}

	// Fallback to cold registry
	h.logger.Debug().
		Str("backend", "cold").
		Str("backend_url", h.config.Registry.Cold.URL).
		Str("name", name).
		Str("digest", digest).
		Msg("Attempting to check blob in cold registry")

	if h.handleBlobRequest(w, r, &h.config.Registry.Cold, name, digest) {
		h.logger.Info().
			Str("handler", "HandleBlob").
			Str("name", name).
			Str("digest", digest).
			Str("backend", "cold").
			Dur("duration_ms", time.Since(startTime)).
			Msg("Request completed")
		return
	}

	// Not found in either registry
	h.logger.Warn().
		Str("name", name).
		Str("digest", digest).
		Str("client_ip", h.getClientIP(r)).
		Msg("Blob not found in any registry")
	h.writeErrorResponse(w, "BLOB_UNKNOWN", "blob unknown", http.StatusNotFound)

	h.logger.Info().
		Str("handler", "HandleBlob").
		Str("name", name).
		Str("digest", digest).
		Int("status", http.StatusNotFound).
		Dur("duration_ms", time.Since(startTime)).
		Msg("Request completed with not found")
}

// proxyManifest proxies a manifest request to the specified backend
func (h *Handler) proxyManifest(w http.ResponseWriter, r *http.Request, backend *config.RegistryBackend, name, reference string) bool {
	backendStartTime := time.Now()
	backendURL := fmt.Sprintf("%s/v2/%s/manifests/%s", strings.TrimSuffix(backend.URL, "/"), name, reference)

	hasAuth := backend.Username != "" && backend.Password != ""
	h.logger.Debug().
		Str("backend_url", backendURL).
		Str("method", r.Method).
		Bool("has_auth", hasAuth).
		Int("custom_headers_count", len(backend.Headers)).
		Str("name", name).
		Str("reference", reference).
		Msg("Proxying manifest request to backend")

	req, err := http.NewRequestWithContext(r.Context(), r.Method, backendURL, nil)
	if err != nil {
		h.logger.Error().
			Err(err).
			Str("backend_url", backendURL).
			Msg("Failed to create manifest request")
		return false
	}

	// Copy headers (but exclude Authorization to avoid conflicts)
	for k, v := range r.Header {
		// Skip Authorization header - we'll set it explicitly if auth is configured
		if strings.EqualFold(k, "Authorization") {
			continue
		}
		req.Header[k] = v
	}

	// Add authentication if configured
	if hasAuth {
		req.SetBasicAuth(backend.Username, backend.Password)
		h.logger.Debug().
			Str("backend_url", backendURL).
			Str("username", backend.Username).
			Msg("Added basic authentication to backend request")
	}

	// Add custom headers
	for k, v := range backend.Headers {
		req.Header.Set(k, v)
	}

	resp, err := h.client.Do(req)
	backendDuration := time.Since(backendStartTime)
	if err != nil {
		h.logger.Error().
			Err(err).
			Str("backend_url", backendURL).
			Dur("duration_ms", backendDuration).
			Msg("Failed to proxy manifest request to backend")
		return false
	}
	defer resp.Body.Close()

	h.logger.Debug().
		Str("backend_url", backendURL).
		Int("status_code", resp.StatusCode).
		Int64("content_length", resp.ContentLength).
		Dur("duration_ms", backendDuration).
		Msg("Backend response received")

	if resp.StatusCode == http.StatusNotFound {
		h.logger.Debug().
			Str("backend_url", backendURL).
			Str("name", name).
			Str("reference", reference).
			Dur("duration_ms", backendDuration).
			Msg("Manifest not found in backend")
		return false
	}

	if resp.StatusCode != http.StatusOK {
		// Read error response body for detailed error information
		bodyBytes, _ := io.ReadAll(resp.Body)
		errorBody := string(bodyBytes)

		// If 401 and Bearer token authentication is required, try to get token and retry
		if resp.StatusCode == http.StatusUnauthorized && hasAuth {
			wwwAuth := resp.Header.Get("Www-Authenticate")
			realm, service, scope := parseWwwAuthenticate(wwwAuth)

			if realm != "" {
				h.logger.Debug().
					Str("realm", realm).
					Str("service", service).
					Str("scope", scope).
					Msg("Attempting to get Bearer token for retry")

				// Get Bearer token
				token, err := h.getBearerToken(realm, service, scope, backend.Username, backend.Password, backend.Headers)
				if err != nil {
					h.logger.Warn().
						Err(err).
						Str("backend_url", backendURL).
						Str("name", name).
						Str("reference", reference).
						Str("error_response", errorBody).
						Str("www_authenticate", wwwAuth).
						Dur("duration_ms", backendDuration).
						Msg("Failed to get Bearer token, authentication failed")
					return false
				}

				// Retry request with Bearer token
				h.logger.Debug().
					Str("backend_url", backendURL).
					Msg("Retrying request with Bearer token")

				retryReq, err := http.NewRequestWithContext(r.Context(), r.Method, backendURL, nil)
				if err != nil {
					h.logger.Error().
						Err(err).
						Str("backend_url", backendURL).
						Msg("Failed to create retry manifest request")
					return false
				}

				// Copy headers (but exclude Authorization)
				for k, v := range r.Header {
					if strings.EqualFold(k, "Authorization") {
						continue
					}
					retryReq.Header[k] = v
				}

				// Set Bearer token
				retryReq.Header.Set("Authorization", "Bearer "+token)

				// Add custom headers
				for k, v := range backend.Headers {
					retryReq.Header.Set(k, v)
				}

				retryResp, err := h.client.Do(retryReq)
				retryDuration := time.Since(backendStartTime)
				if err != nil {
					h.logger.Error().
						Err(err).
						Str("backend_url", backendURL).
						Dur("duration_ms", retryDuration).
						Msg("Failed to retry manifest request with Bearer token")
					return false
				}
				defer retryResp.Body.Close()

				if retryResp.StatusCode == http.StatusNotFound {
					h.logger.Debug().
						Str("backend_url", backendURL).
						Str("name", name).
						Str("reference", reference).
						Dur("duration_ms", retryDuration).
						Msg("Manifest not found in backend (after token retry)")
					return false
				}

				if retryResp.StatusCode != http.StatusOK {
					retryBodyBytes, _ := io.ReadAll(retryResp.Body)
					h.logger.Warn().
						Int("status", retryResp.StatusCode).
						Str("backend_url", backendURL).
						Str("name", name).
						Str("reference", reference).
						Str("error_response", string(retryBodyBytes)).
						Dur("duration_ms", retryDuration).
						Msg("Backend returned non-OK status after Bearer token retry")
					return false
				}

				// Success with Bearer token - copy response
				for k, v := range retryResp.Header {
					w.Header()[k] = v
				}

				w.WriteHeader(retryResp.StatusCode)

				bodyStartTime := time.Now()
				bytesCopied, err := io.Copy(w, retryResp.Body)
				bodyDuration := time.Since(bodyStartTime)
				if err != nil {
					h.logger.Error().
						Err(err).
						Str("backend_url", backendURL).
						Int64("bytes_copied", bytesCopied).
						Dur("body_copy_duration_ms", bodyDuration).
						Msg("Failed to copy manifest response body")
					return false
				}

				h.logger.Info().
					Str("backend_url", backendURL).
					Str("name", name).
					Str("reference", reference).
					Int("status_code", retryResp.StatusCode).
					Int64("bytes_copied", bytesCopied).
					Dur("backend_duration_ms", retryDuration).
					Dur("body_copy_duration_ms", bodyDuration).
					Msg("Successfully proxied manifest from backend (with Bearer token)")

				return true
			}
		}

		if resp.StatusCode == http.StatusUnauthorized {
			h.logger.Warn().
				Int("status", resp.StatusCode).
				Str("backend_url", backendURL).
				Str("name", name).
				Str("reference", reference).
				Str("error_response", errorBody).
				Str("www_authenticate", resp.Header.Get("Www-Authenticate")).
				Dur("duration_ms", backendDuration).
				Msg("Backend returned 401 Unauthorized - authentication failed")
		} else {
			h.logger.Warn().
				Int("status", resp.StatusCode).
				Str("backend_url", backendURL).
				Str("name", name).
				Str("reference", reference).
				Str("error_response", errorBody).
				Dur("duration_ms", backendDuration).
				Msg("Backend returned non-OK status")
		}
		return false
	}

	// Copy response headers
	for k, v := range resp.Header {
		w.Header()[k] = v
	}

	w.WriteHeader(resp.StatusCode)

	// Copy response body
	bodyStartTime := time.Now()
	bytesCopied, err := io.Copy(w, resp.Body)
	bodyDuration := time.Since(bodyStartTime)
	if err != nil {
		h.logger.Error().
			Err(err).
			Str("backend_url", backendURL).
			Int64("bytes_copied", bytesCopied).
			Dur("body_copy_duration_ms", bodyDuration).
			Msg("Failed to copy manifest response body")
		return false
	}

	h.logger.Info().
		Str("backend_url", backendURL).
		Str("name", name).
		Str("reference", reference).
		Int("status_code", resp.StatusCode).
		Int64("bytes_copied", bytesCopied).
		Dur("backend_duration_ms", backendDuration).
		Dur("body_copy_duration_ms", bodyDuration).
		Msg("Successfully proxied manifest from backend")

	return true
}

// proxyBlob proxies a blob request to the specified backend
func (h *Handler) proxyBlob(w http.ResponseWriter, r *http.Request, backend *config.RegistryBackend, name, digest string) bool {
	backendStartTime := time.Now()
	backendURL := fmt.Sprintf("%s/v2/%s/blobs/%s", strings.TrimSuffix(backend.URL, "/"), name, digest)

	hasAuth := backend.Username != "" && backend.Password != ""
	h.logger.Debug().
		Str("backend_url", backendURL).
		Str("method", r.Method).
		Bool("has_auth", hasAuth).
		Int("custom_headers_count", len(backend.Headers)).
		Str("name", name).
		Str("digest", digest).
		Msg("Proxying blob request to backend")

	req, err := http.NewRequestWithContext(r.Context(), r.Method, backendURL, nil)
	if err != nil {
		h.logger.Error().
			Err(err).
			Str("backend_url", backendURL).
			Msg("Failed to create blob request")
		return false
	}

	// Copy headers (but exclude Authorization to avoid conflicts)
	for k, v := range r.Header {
		// Skip Authorization header - we'll set it explicitly if auth is configured
		if strings.EqualFold(k, "Authorization") {
			continue
		}
		req.Header[k] = v
	}

	// Add authentication if configured
	if hasAuth {
		req.SetBasicAuth(backend.Username, backend.Password)
		h.logger.Debug().
			Str("backend_url", backendURL).
			Str("username", backend.Username).
			Msg("Added basic authentication to backend request")
	}

	// Add custom headers
	for k, v := range backend.Headers {
		req.Header.Set(k, v)
	}

	resp, err := h.client.Do(req)
	backendDuration := time.Since(backendStartTime)
	if err != nil {
		h.logger.Error().
			Err(err).
			Str("backend_url", backendURL).
			Dur("duration_ms", backendDuration).
			Msg("Failed to proxy blob request to backend")
		return false
	}
	defer resp.Body.Close()

	h.logger.Debug().
		Str("backend_url", backendURL).
		Int("status_code", resp.StatusCode).
		Int64("content_length", resp.ContentLength).
		Dur("duration_ms", backendDuration).
		Msg("Backend response received")

	if resp.StatusCode == http.StatusNotFound {
		h.logger.Debug().
			Str("backend_url", backendURL).
			Str("name", name).
			Str("digest", digest).
			Dur("duration_ms", backendDuration).
			Msg("Blob not found in backend")
		return false
	}

	if resp.StatusCode != http.StatusOK {
		// Read error response body for detailed error information
		bodyBytes, _ := io.ReadAll(resp.Body)
		errorBody := string(bodyBytes)

		// If 401 and Bearer token authentication is required, try to get token and retry
		if resp.StatusCode == http.StatusUnauthorized && hasAuth {
			wwwAuth := resp.Header.Get("Www-Authenticate")
			realm, service, scope := parseWwwAuthenticate(wwwAuth)

			if realm != "" {
				h.logger.Debug().
					Str("realm", realm).
					Str("service", service).
					Str("scope", scope).
					Msg("Attempting to get Bearer token for blob retry")

				// Get Bearer token
				token, err := h.getBearerToken(realm, service, scope, backend.Username, backend.Password, backend.Headers)
				if err != nil {
					h.logger.Warn().
						Err(err).
						Str("backend_url", backendURL).
						Str("name", name).
						Str("digest", digest).
						Str("error_response", errorBody).
						Str("www_authenticate", wwwAuth).
						Dur("duration_ms", backendDuration).
						Msg("Failed to get Bearer token for blob, authentication failed")
					return false
				}

				// Retry request with Bearer token
				h.logger.Debug().
					Str("backend_url", backendURL).
					Msg("Retrying blob request with Bearer token")

				retryReq, err := http.NewRequestWithContext(r.Context(), r.Method, backendURL, nil)
				if err != nil {
					h.logger.Error().
						Err(err).
						Str("backend_url", backendURL).
						Msg("Failed to create retry blob request")
					return false
				}

				// Copy headers (but exclude Authorization)
				for k, v := range r.Header {
					if strings.EqualFold(k, "Authorization") {
						continue
					}
					retryReq.Header[k] = v
				}

				// Set Bearer token
				retryReq.Header.Set("Authorization", "Bearer "+token)

				// Add custom headers
				for k, v := range backend.Headers {
					retryReq.Header.Set(k, v)
				}

				retryResp, err := h.client.Do(retryReq)
				retryDuration := time.Since(backendStartTime)
				if err != nil {
					h.logger.Error().
						Err(err).
						Str("backend_url", backendURL).
						Dur("duration_ms", retryDuration).
						Msg("Failed to retry blob request with Bearer token")
					return false
				}
				defer retryResp.Body.Close()

				if retryResp.StatusCode == http.StatusNotFound {
					h.logger.Debug().
						Str("backend_url", backendURL).
						Str("name", name).
						Str("digest", digest).
						Dur("duration_ms", retryDuration).
						Msg("Blob not found in backend (after token retry)")
					return false
				}

				// Handle 307 redirect - follow the redirect with Bearer token
				if retryResp.StatusCode == http.StatusTemporaryRedirect || retryResp.StatusCode == http.StatusFound {
					location := retryResp.Header.Get("Location")
					if location == "" {
						retryBodyBytes, _ := io.ReadAll(retryResp.Body)
						h.logger.Warn().
							Int("status", retryResp.StatusCode).
							Str("backend_url", backendURL).
							Str("name", name).
							Str("digest", digest).
							Str("error_response", string(retryBodyBytes)).
							Dur("duration_ms", retryDuration).
							Msg("Backend returned redirect but no Location header")
						return false
					}

					h.logger.Debug().
						Str("backend_url", backendURL).
						Str("redirect_location", location).
						Msg("Following redirect with Bearer token")

					// Follow redirect with Bearer token
					redirectReq, err := http.NewRequestWithContext(r.Context(), r.Method, location, nil)
					if err != nil {
						h.logger.Error().
							Err(err).
							Str("redirect_location", location).
							Msg("Failed to create redirect request")
						return false
					}

					// Copy headers (but exclude Authorization)
					for k, v := range r.Header {
						if strings.EqualFold(k, "Authorization") {
							continue
						}
						redirectReq.Header[k] = v
					}

					// Set Bearer token for redirect request
					redirectReq.Header.Set("Authorization", "Bearer "+token)

					// Add custom headers
					for k, v := range backend.Headers {
						redirectReq.Header.Set(k, v)
					}

					redirectResp, err := h.client.Do(redirectReq)
					redirectDuration := time.Since(backendStartTime)
					if err != nil {
						h.logger.Error().
							Err(err).
							Str("redirect_location", location).
							Dur("duration_ms", redirectDuration).
							Msg("Failed to follow redirect with Bearer token")
						return false
					}
					defer redirectResp.Body.Close()

					if redirectResp.StatusCode == http.StatusNotFound {
						h.logger.Debug().
							Str("redirect_location", location).
							Str("name", name).
							Str("digest", digest).
							Dur("duration_ms", redirectDuration).
							Msg("Blob not found after following redirect")
						return false
					}

					if redirectResp.StatusCode != http.StatusOK {
						redirectBodyBytes, _ := io.ReadAll(redirectResp.Body)
						h.logger.Warn().
							Int("status", redirectResp.StatusCode).
							Str("redirect_location", location).
							Str("name", name).
							Str("digest", digest).
							Str("error_response", string(redirectBodyBytes)).
							Dur("duration_ms", redirectDuration).
							Msg("Backend returned non-OK status after following redirect")
						return false
					}

					// Success after following redirect - copy response
					for k, v := range redirectResp.Header {
						w.Header()[k] = v
					}

					w.WriteHeader(redirectResp.StatusCode)

					bodyStartTime := time.Now()
					bytesCopied, err := io.Copy(w, redirectResp.Body)
					bodyDuration := time.Since(bodyStartTime)
					if err != nil {
						h.logger.Error().
							Err(err).
							Str("redirect_location", location).
							Int64("bytes_copied", bytesCopied).
							Dur("body_copy_duration_ms", bodyDuration).
							Msg("Failed to copy blob response body after redirect")
						return false
					}

					h.logger.Info().
						Str("backend_url", backendURL).
						Str("redirect_location", location).
						Str("name", name).
						Str("digest", digest).
						Int("status_code", redirectResp.StatusCode).
						Int64("bytes_copied", bytesCopied).
						Dur("backend_duration_ms", redirectDuration).
						Dur("body_copy_duration_ms", bodyDuration).
						Msg("Successfully proxied blob from backend (after following redirect with Bearer token)")

					return true
				}

				if retryResp.StatusCode != http.StatusOK {
					retryBodyBytes, _ := io.ReadAll(retryResp.Body)
					h.logger.Warn().
						Int("status", retryResp.StatusCode).
						Str("backend_url", backendURL).
						Str("name", name).
						Str("digest", digest).
						Str("error_response", string(retryBodyBytes)).
						Dur("duration_ms", retryDuration).
						Msg("Backend returned non-OK status after Bearer token retry")
					return false
				}

				// Success with Bearer token - copy response
				for k, v := range retryResp.Header {
					w.Header()[k] = v
				}

				w.WriteHeader(retryResp.StatusCode)

				bodyStartTime := time.Now()
				bytesCopied, err := io.Copy(w, retryResp.Body)
				bodyDuration := time.Since(bodyStartTime)
				if err != nil {
					h.logger.Error().
						Err(err).
						Str("backend_url", backendURL).
						Int64("bytes_copied", bytesCopied).
						Dur("body_copy_duration_ms", bodyDuration).
						Msg("Failed to copy blob response body")
					return false
				}

				h.logger.Info().
					Str("backend_url", backendURL).
					Str("name", name).
					Str("digest", digest).
					Int("status_code", retryResp.StatusCode).
					Int64("bytes_copied", bytesCopied).
					Dur("backend_duration_ms", retryDuration).
					Dur("body_copy_duration_ms", bodyDuration).
					Msg("Successfully proxied blob from backend (with Bearer token)")

				return true
			}
		}

		h.logger.Warn().
			Int("status", resp.StatusCode).
			Str("backend_url", backendURL).
			Str("name", name).
			Str("digest", digest).
			Dur("duration_ms", backendDuration).
			Msg("Backend returned non-OK status")
		return false
	}

	// Copy response headers
	for k, v := range resp.Header {
		w.Header()[k] = v
	}

	w.WriteHeader(resp.StatusCode)

	// Copy response body
	bodyStartTime := time.Now()
	bytesCopied, err := io.Copy(w, resp.Body)
	bodyDuration := time.Since(bodyStartTime)
	if err != nil {
		h.logger.Error().
			Err(err).
			Str("backend_url", backendURL).
			Int64("bytes_copied", bytesCopied).
			Dur("body_copy_duration_ms", bodyDuration).
			Msg("Failed to copy blob response body")
		return false
	}

	h.logger.Info().
		Str("backend_url", backendURL).
		Str("name", name).
		Str("digest", digest).
		Int("status_code", resp.StatusCode).
		Int64("bytes_copied", bytesCopied).
		Dur("backend_duration_ms", backendDuration).
		Dur("body_copy_duration_ms", bodyDuration).
		Msg("Successfully proxied blob from backend")

	return true
}

// redirectBlob redirects blob requests to the backend with 307
// The client will use its local credentials (from docker login) to authenticate with the backend.
// If wwwAuth is provided, it will be included in the response headers to help the client authenticate.
func (h *Handler) redirectBlob(w http.ResponseWriter, r *http.Request, backend *config.RegistryBackend, name, digest string, wwwAuth string) bool {
	backendURL := fmt.Sprintf("%s/v2/%s/blobs/%s", strings.TrimSuffix(backend.URL, "/"), name, digest)

	h.logger.Info().
		Str("backend_url", backendURL).
		Str("name", name).
		Str("digest", digest).
		Str("www_authenticate", wwwAuth).
		Msg("Blob found, redirecting client to backend (client will handle authentication)")

	w.Header().Set("Location", backendURL)
	// Include Www-Authenticate header if provided, so Docker client knows how to authenticate
	if wwwAuth != "" {
		w.Header().Set("Www-Authenticate", wwwAuth)
	}
	w.WriteHeader(http.StatusTemporaryRedirect)
	return true
}

// handleBlobRequest handles blob requests by checking existence with authentication and redirecting with 307.
// This function uses server-side credentials to authenticate with the backend registry, then extracts the
// redirect URL (usually a signed storage URL) and returns it to the client via 307 redirect.
// This approach solves the authentication problem while maintaining the performance benefits of 307 redirects.
func (h *Handler) handleBlobRequest(w http.ResponseWriter, r *http.Request, backend *config.RegistryBackend, name, digest string) bool {
	backendStartTime := time.Now()
	backendURL := fmt.Sprintf("%s/v2/%s/blobs/%s", strings.TrimSuffix(backend.URL, "/"), name, digest)

	hasAuth := backend.Username != "" && backend.Password != ""
	h.logger.Debug().
		Str("backend_url", backendURL).
		Bool("has_auth", hasAuth).
		Int("custom_headers_count", len(backend.Headers)).
		Str("name", name).
		Str("digest", digest).
		Msg("检查后端 blob 是否存在（带认证）")

	// Create HEAD request with authentication
	req, err := http.NewRequestWithContext(r.Context(), "HEAD", backendURL, nil)
	if err != nil {
		h.logger.Error().
			Err(err).
			Str("backend_url", backendURL).
			Msg("创建 blob HEAD 请求失败")
		return false
	}

	// Add Basic Auth if configured
	if hasAuth {
		req.SetBasicAuth(backend.Username, backend.Password)
		h.logger.Debug().
			Str("backend_url", backendURL).
			Str("username", backend.Username).
			Msg("为 HEAD 请求添加 Basic Auth 认证")
	}

	// Add custom headers
	for k, v := range backend.Headers {
		req.Header.Set(k, v)
	}

	// Execute HEAD request
	resp, err := h.client.Do(req)
	checkDuration := time.Since(backendStartTime)
	if err != nil {
		h.logger.Error().
			Err(err).
			Str("backend_url", backendURL).
			Dur("duration_ms", checkDuration).
			Msg("检查 blob 存在性失败")
		return false
	}
	defer resp.Body.Close()

	h.logger.Debug().
		Str("backend_url", backendURL).
		Int("status_code", resp.StatusCode).
		Int64("content_length", resp.ContentLength).
		Dur("duration_ms", checkDuration).
		Msg("收到后端 HEAD 响应")

	// Handle 401 Unauthorized - try Bearer token authentication
	var bearerToken string
	if resp.StatusCode == http.StatusUnauthorized && hasAuth {
		wwwAuth := resp.Header.Get("Www-Authenticate")
		realm, service, scope := parseWwwAuthenticate(wwwAuth)

		if realm != "" {
			h.logger.Debug().
				Str("realm", realm).
				Str("service", service).
				Str("scope", scope).
				Msg("检测到 Bearer 认证要求，尝试获取 token")

			// Get Bearer token
			token, err := h.getBearerToken(realm, service, scope, backend.Username, backend.Password, backend.Headers)
			if err != nil {
				h.logger.Warn().
					Err(err).
					Str("backend_url", backendURL).
					Str("www_authenticate", wwwAuth).
					Dur("duration_ms", checkDuration).
					Msg("获取 Bearer token 失败，认证失败")
				return false
			}

			bearerToken = token // Save token for later use
			h.logger.Debug().
				Str("backend_url", backendURL).
				Msg("成功获取 Bearer token，使用 token 重试 HEAD 请求")

			// Retry HEAD request with Bearer token
			retryReq, err := http.NewRequestWithContext(r.Context(), "HEAD", backendURL, nil)
			if err != nil {
				h.logger.Error().
					Err(err).
					Str("backend_url", backendURL).
					Msg("创建 Bearer token 重试请求失败")
				return false
			}

			// Set Bearer token
			retryReq.Header.Set("Authorization", "Bearer "+token)

			// Add custom headers
			for k, v := range backend.Headers {
				retryReq.Header.Set(k, v)
			}

			// Execute retry request
			retryResp, err := h.client.Do(retryReq)
			retryDuration := time.Since(backendStartTime)
			if err != nil {
				h.logger.Error().
					Err(err).
					Str("backend_url", backendURL).
					Dur("duration_ms", retryDuration).
					Msg("使用 Bearer token 重试 HEAD 请求失败")
				return false
			}
			defer retryResp.Body.Close()

			h.logger.Debug().
				Str("backend_url", backendURL).
				Int("status_code", retryResp.StatusCode).
				Dur("duration_ms", retryDuration).
				Msg("收到 Bearer token 重试响应")

			// Update resp to retryResp for subsequent processing
			resp = retryResp
			checkDuration = retryDuration
		}
	}

	// Handle 404 Not Found
	if resp.StatusCode == http.StatusNotFound {
		h.logger.Debug().
			Str("backend_url", backendURL).
			Str("name", name).
			Str("digest", digest).
			Dur("duration_ms", checkDuration).
			Msg("Blob 在后端不存在")
		return false
	}

	// Handle redirect responses (307, 302, 301) - backend is redirecting to storage service
	if resp.StatusCode == http.StatusTemporaryRedirect ||
		resp.StatusCode == http.StatusFound ||
		resp.StatusCode == http.StatusMovedPermanently {
		location := resp.Header.Get("Location")
		if location == "" {
			h.logger.Warn().
				Int("status", resp.StatusCode).
				Str("backend_url", backendURL).
				Str("name", name).
				Str("digest", digest).
				Dur("duration_ms", checkDuration).
				Msg("后端返回重定向但缺少 Location 头")
			return false
		}

		h.logger.Info().
			Str("backend_url", backendURL).
			Str("redirect_location", location).
			Str("name", name).
			Str("digest", digest).
			Int("status_code", resp.StatusCode).
			Dur("duration_ms", checkDuration).
			Msg("后端返回重定向 URL（通常是签名存储 URL），返回 307 给客户端")

		// Redirect client to the storage service URL
		w.Header().Set("Location", location)
		w.WriteHeader(http.StatusTemporaryRedirect)
		return true
	}

	// Handle 200 OK - blob exists, but we need to check if backend will redirect on GET
	// Cloud registries (like Tencent CCR) return 200 on HEAD but 307 on GET to storage URL
	if resp.StatusCode == http.StatusOK {
		h.logger.Debug().
			Str("backend_url", backendURL).
			Str("name", name).
			Str("digest", digest).
			Dur("duration_ms", checkDuration).
			Msg("HEAD 请求返回 200，现在发送 GET 请求获取可能的重定向 URL")

		if hasAuth {
			// We need to make a GET request with the same authentication
			getReq, err := http.NewRequestWithContext(r.Context(), "GET", backendURL, nil)
			if err != nil {
				h.logger.Error().
					Err(err).
					Str("backend_url", backendURL).
					Msg("创建 GET 请求失败")
				return false
			}

			// Use Bearer token if we have one, otherwise use Basic Auth
			if bearerToken != "" {
				getReq.Header.Set("Authorization", "Bearer "+bearerToken)
				h.logger.Debug().
					Str("backend_url", backendURL).
					Msg("使用 Bearer Token 发送 GET 请求")
			} else {
				getReq.SetBasicAuth(backend.Username, backend.Password)
				h.logger.Debug().
					Str("backend_url", backendURL).
					Msg("使用 Basic Auth 发送 GET 请求")
			}

			// Add custom headers
			for k, v := range backend.Headers {
				getReq.Header.Set(k, v)
			}

			// Execute GET request
			getResp, err := h.client.Do(getReq)
			getDuration := time.Since(backendStartTime)
			if err != nil {
				h.logger.Error().
					Err(err).
					Str("backend_url", backendURL).
					Dur("duration_ms", getDuration).
					Msg("GET 请求失败")
				return false
			}
			defer getResp.Body.Close()

			h.logger.Debug().
				Str("backend_url", backendURL).
				Int("status_code", getResp.StatusCode).
				Dur("duration_ms", getDuration).
				Msg("收到 GET 响应")

			// Check if GET returns a redirect (this is what we want!)
			if getResp.StatusCode == http.StatusTemporaryRedirect ||
				getResp.StatusCode == http.StatusFound ||
				getResp.StatusCode == http.StatusMovedPermanently {
				location := getResp.Header.Get("Location")
				if location == "" {
					h.logger.Warn().
						Int("status", getResp.StatusCode).
						Str("backend_url", backendURL).
						Msg("GET 返回重定向但缺少 Location 头")
					return false
				}

				h.logger.Info().
					Str("backend_url", backendURL).
					Str("redirect_location", location).
					Str("name", name).
					Str("digest", digest).
					Int("status_code", getResp.StatusCode).
					Dur("duration_ms", getDuration).
					Msg("GET 请求返回重定向 URL（签名存储 URL），返回 307 给客户端")

				// Redirect client to the storage service URL
				w.Header().Set("Location", location)
				w.WriteHeader(http.StatusTemporaryRedirect)
				return true
			}

			// If GET returns 200, we need to proxy the actual blob data
			if getResp.StatusCode == http.StatusOK {
				h.logger.Info().
					Str("backend_url", backendURL).
					Str("name", name).
					Str("digest", digest).
					Int64("content_length", getResp.ContentLength).
					Dur("duration_ms", getDuration).
					Msg("GET 返回实际 blob 数据，将代理数据流")

				// Copy response headers
				for k, v := range getResp.Header {
					w.Header()[k] = v
				}
				w.WriteHeader(getResp.StatusCode)

				// Copy response body
				bodyStartTime := time.Now()
				bytesCopied, err := io.Copy(w, getResp.Body)
				bodyDuration := time.Since(bodyStartTime)
				if err != nil {
					h.logger.Error().
						Err(err).
						Str("backend_url", backendURL).
						Int64("bytes_copied", bytesCopied).
						Dur("body_copy_duration_ms", bodyDuration).
						Msg("代理 blob 数据失败")
					return false
				}

				h.logger.Info().
					Str("backend_url", backendURL).
					Str("name", name).
					Str("digest", digest).
					Int64("bytes_copied", bytesCopied).
					Dur("total_duration_ms", getDuration).
					Dur("body_copy_duration_ms", bodyDuration).
					Msg("成功代理 blob 数据")
				return true
			}

			// Other status codes from GET
			h.logger.Warn().
				Int("status", getResp.StatusCode).
				Str("backend_url", backendURL).
				Str("name", name).
				Str("digest", digest).
				Dur("duration_ms", getDuration).
				Msg("GET 请求返回非预期状态码")
			return false
		}

		// Fallback: if no auth, just redirect to backend URL
		h.logger.Info().
			Str("backend_url", backendURL).
			Str("name", name).
			Str("digest", digest).
			Dur("duration_ms", checkDuration).
			Msg("Blob 在后端可访问（无需认证），返回 307 重定向到后端 URL")
		return h.redirectBlob(w, r, backend, name, digest, "")
	}

	// Handle other status codes (403, 500, etc.)
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		h.logger.Warn().
			Int("status", resp.StatusCode).
			Str("backend_url", backendURL).
			Str("name", name).
			Str("digest", digest).
			Str("www_authenticate", resp.Header.Get("Www-Authenticate")).
			Dur("duration_ms", checkDuration).
			Msg("认证失败，无法访问后端 blob")
		return false
	}

	// Other unexpected status codes
	h.logger.Warn().
		Int("status", resp.StatusCode).
		Str("backend_url", backendURL).
		Str("name", name).
		Str("digest", digest).
		Dur("duration_ms", checkDuration).
		Msg("后端返回非预期状态码")
	return false
}
