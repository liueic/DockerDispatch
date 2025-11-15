package main

import (
    "context"
    "fmt"
    "net/http"
    "os"
    "os/signal"
    "strings"
    "syscall"
    "time"

    "mirror-registry/internal/config"
    "mirror-registry/internal/handler"
    "mirror-registry/internal/logger"

    "github.com/gorilla/mux"
)

func main() {
    // Initialize logger
    log := logger.Initialize()

    // Load configuration
    cfg, err := config.Load()
    if err != nil {
        log.Fatal().Err(err).Msg("Failed to load configuration")
    }

    // Create router
    router := mux.NewRouter()

    // Initialize handler with configuration
    h := handler.New(cfg, log)

    // Register routes
    // Root path handler
    router.HandleFunc("/", h.HandleRoot).Methods("GET")
    
    // Docker Registry API v2 endpoints
    router.HandleFunc("/v2/", h.HandleV2).Methods("GET")
    
    // Manifest and blob endpoints - use PathPrefix to support image names with slashes
    router.PathPrefix("/v2/").MatcherFunc(func(r *http.Request, rm *mux.RouteMatch) bool {
        path := r.URL.Path
        return strings.Contains(path, "/manifests/") || strings.Contains(path, "/blobs/")
    }).HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        path := r.URL.Path
        if strings.Contains(path, "/manifests/") {
            h.HandleManifest(w, r)
        } else if strings.Contains(path, "/blobs/") {
            h.HandleBlob(w, r)
        } else {
            h.HandleNotFound(w, r)
        }
    }).Methods("GET")

    // Health check endpoint
    router.HandleFunc("/health", h.HandleHealth).Methods("GET")
    
    // 404 handler for unmatched routes
    router.NotFoundHandler = http.HandlerFunc(h.HandleNotFound)

    // Create HTTP server
    srv := &http.Server{
        Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
        Handler:      router,
        ReadTimeout:  30 * time.Second,
        WriteTimeout: 30 * time.Second,
        IdleTimeout:  120 * time.Second,
    }

    // Start server in a goroutine
    go func() {
        log.Info().Int("port", cfg.Server.Port).Msg("Starting mirror registry server")
        if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            log.Fatal().Err(err).Msg("Server failed to start")
        }
    }()

    // Wait for interrupt signal to gracefully shutdown the server
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit
    log.Info().Msg("Shutting down server...")

    // Give outstanding requests 30 seconds to complete
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    if err := srv.Shutdown(ctx); err != nil {
        log.Fatal().Err(err).Msg("Server forced to shutdown")
    }

    log.Info().Msg("Server exited")
}