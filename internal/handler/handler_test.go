package handler

import (
    "net/http"
    "net/http/httptest"
    "testing"

    "mirror-registry/internal/config"
    "mirror-registry/internal/logger"

    "github.com/stretchr/testify/assert"
)

func TestHandleV2(t *testing.T) {
    cfg := &config.Config{
        Server: config.ServerConfig{Port: 5000},
    }

    h := New(cfg, logger.Initialize())

    req, err := http.NewRequest("GET", "/v2/", nil)
    assert.NoError(t, err)

    rr := httptest.NewRecorder()
    handler := http.HandlerFunc(h.HandleV2)

    handler.ServeHTTP(rr, req)

    assert.Equal(t, http.StatusOK, rr.Code)
    assert.Equal(t, "registry/2.0", rr.Header().Get("Docker-Distribution-Api-Version"))
}

func TestHandleHealth(t *testing.T) {
    cfg := &config.Config{
        Server: config.ServerConfig{Port: 5000},
    }

    h := New(cfg, logger.Initialize())

    req, err := http.NewRequest("GET", "/health", nil)
    assert.NoError(t, err)

    rr := httptest.NewRecorder()
    handler := http.HandlerFunc(h.HandleHealth)

    handler.ServeHTTP(rr, req)

    assert.Equal(t, http.StatusOK, rr.Code)
    assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
    assert.Equal(t, `{"status":"healthy"}`, rr.Body.String())
}