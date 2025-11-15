package handler

import (
    "fmt"
    "io"
    "net/http"
    "strings"
    "time"

    "mirror-registry/internal/config"

    "github.com/gorilla/mux"
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

// HandleV2 handles the /v2/ endpoint for API version detection
func (h *Handler) HandleV2(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    w.Write([]byte("{}"))
}

// HandleHealth handles health check requests
func (h *Handler) HandleHealth(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    w.Write([]byte(`{"status":"healthy"}`))
}

// HandleManifest handles manifest requests with fallback logic
func (h *Handler) HandleManifest(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    name := vars["name"]
    reference := vars["reference"]

    h.logger.Info().
        Str("name", name).
        Str("reference", reference).
        Msg("Handling manifest request")

    // Try hot registry first
    if h.proxyManifest(w, r, &h.config.Registry.Hot, name, reference) {
        return
    }

    // Fallback to cold registry
    if h.proxyManifest(w, r, &h.config.Registry.Cold, name, reference) {
        return
    }

    // Not found in either registry
    h.logger.Warn().
        Str("name", name).
        Str("reference", reference).
        Msg("Manifest not found in any registry")
    http.Error(w, "MANIFEST_UNKNOWN", http.StatusNotFound)
}

// HandleBlob handles blob requests with 307 redirect logic
func (h *Handler) HandleBlob(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    name := vars["name"]
    digest := vars["digest"]

    h.logger.Info().
        Str("name", name).
        Str("digest", digest).
        Msg("Handling blob request")

    // Try hot registry first
    if h.redirectBlob(w, r, &h.config.Registry.Hot, name, digest) {
        return
    }

    // Fallback to cold registry
    if h.redirectBlob(w, r, &h.config.Registry.Cold, name, digest) {
        return
    }

    // Not found in either registry
    h.logger.Warn().
        Str("name", name).
        Str("digest", digest).
        Msg("Blob not found in any registry")
    http.Error(w, "BLOB_UNKNOWN", http.StatusNotFound)
}

// proxyManifest proxies a manifest request to the specified backend
func (h *Handler) proxyManifest(w http.ResponseWriter, r *http.Request, backend *config.RegistryBackend, name, reference string) bool {
    backendURL := fmt.Sprintf("%s/v2/%s/manifests/%s", strings.TrimSuffix(backend.URL, "/"), name, reference)

    req, err := http.NewRequestWithContext(r.Context(), r.Method, backendURL, nil)
    if err != nil {
        h.logger.Error().Err(err).Msg("Failed to create manifest request")
        return false
    }

    // Copy headers
    for k, v := range r.Header {
        req.Header[k] = v
    }

    // Add authentication if configured
    if backend.Username != "" && backend.Password != "" {
        req.SetBasicAuth(backend.Username, backend.Password)
    }

    // Add custom headers
    for k, v := range backend.Headers {
        req.Header.Set(k, v)
    }

    resp, err := h.client.Do(req)
    if err != nil {
        h.logger.Error().Err(err).Str("backend", backend.URL).Msg("Failed to proxy manifest request")
        return false
    }
    defer resp.Body.Close()

    if resp.StatusCode == http.StatusNotFound {
        h.logger.Debug().Str("backend", backend.URL).Msg("Manifest not found in backend")
        return false
    }

    if resp.StatusCode != http.StatusOK {
        h.logger.Warn().
            Int("status", resp.StatusCode).
            Str("backend", backend.URL).
            Msg("Backend returned non-OK status")
        return false
    }

    // Copy response headers
    for k, v := range resp.Header {
        w.Header()[k] = v
    }

    w.WriteHeader(resp.StatusCode)

    // Copy response body
    if _, err := io.Copy(w, resp.Body); err != nil {
        h.logger.Error().Err(err).Msg("Failed to copy manifest response body")
        return false
    }

    h.logger.Info().
        Str("backend", backend.URL).
        Str("name", name).
        Str("reference", reference).
        Msg("Successfully proxied manifest")

    return true
}

// redirectBlob redirects blob requests to the backend with 307
func (h *Handler) redirectBlob(w http.ResponseWriter, r *http.Request, backend *config.RegistryBackend, name, digest string) bool {
    backendURL := fmt.Sprintf("%s/v2/%s/blobs/%s", strings.TrimSuffix(backend.URL, "/"), name, digest)

    req, err := http.NewRequestWithContext(r.Context(), "HEAD", backendURL, nil)
    if err != nil {
        h.logger.Error().Err(err).Msg("Failed to create blob HEAD request")
        return false
    }

    // Add authentication if configured
    if backend.Username != "" && backend.Password != "" {
        req.SetBasicAuth(backend.Username, backend.Password)
    }

    // Add custom headers
    for k, v := range backend.Headers {
        req.Header.Set(k, v)
    }

    resp, err := h.client.Do(req)
    if err != nil {
        h.logger.Error().Err(err).Str("backend", backend.URL).Msg("Failed to check blob existence")
        return false
    }
    defer resp.Body.Close()

    if resp.StatusCode == http.StatusNotFound {
        h.logger.Debug().Str("backend", backend.URL).Msg("Blob not found in backend")
        return false
    }

    if resp.StatusCode != http.StatusOK {
        h.logger.Warn().
            Int("status", resp.StatusCode).
            Str("backend", backend.URL).
            Msg("Backend returned non-OK status for blob")
        return false
    }

    // Blob exists, redirect client to backend
    h.logger.Info().
        Str("backend", backend.URL).
        Str("name", name).
        Str("digest", digest).
        Msg("Redirecting blob request")

    w.Header().Set("Location", backendURL)
    w.WriteHeader(http.StatusTemporaryRedirect)
    return true
}