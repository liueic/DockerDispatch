package main

import (
    "context"
    "fmt"
    "net/http"
    "os"
    "os/signal"
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
    router.HandleFunc("/v2/", h.HandleV2).Methods("GET")
    router.HandleFunc("/v2/{name}/manifests/{reference}", h.HandleManifest).Methods("GET")
    router.HandleFunc("/v2/{name}/blobs/{digest}", h.HandleBlob).Methods("GET")

    // Health check endpoint
    router.HandleFunc("/health", h.HandleHealth).Methods("GET")

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