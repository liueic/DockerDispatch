package logger

import (
    "os"

    "github.com/rs/zerolog"
    "github.com/rs/zerolog/log"
)

// Initialize initializes the global logger
func Initialize() zerolog.Logger {
    // Set time format to RFC3339
    zerolog.TimeFieldFormat = "2006-01-02T15:04:05Z07:00"

    // Configure output
    output := zerolog.ConsoleWriter{Out: os.Stderr}

    // Create logger
    logger := zerolog.New(output).With().Timestamp().Logger()

    // Set as global logger
    log.Logger = logger

    return logger
}