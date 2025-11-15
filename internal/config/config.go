package config

import (
	"github.com/spf13/viper"
)

// Config represents the application configuration
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Registry RegistryConfig `mapstructure:"registry"`
	Logging  LoggingConfig  `mapstructure:"logging"`
}

// ServerConfig represents server configuration
type ServerConfig struct {
	Port int `mapstructure:"port"`
}

// RegistryConfig represents registry backend configuration
type RegistryConfig struct {
	Hot  RegistryBackend `mapstructure:"hot"`
	Cold RegistryBackend `mapstructure:"cold"`
}

// RegistryBackend represents a single registry backend
type RegistryBackend struct {
	URL      string            `mapstructure:"url"`
	Username string            `mapstructure:"username"`
	Password string            `mapstructure:"password"`
	Headers  map[string]string `mapstructure:"headers"`
}

// LoggingConfig represents logging configuration
type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
}

// Load loads configuration from file and environment variables
func Load() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("/etc/mirror-registry")
	viper.AddConfigPath("$HOME/.mirror-registry")

	// Set defaults
	viper.SetDefault("server.port", 5000)
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "json")

	// Enable environment variable support
	viper.AutomaticEnv()
	viper.SetEnvPrefix("MIRROR")

	// Read configuration file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found, use defaults and environment
		} else {
			return nil, err
		}
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, err
	}

	return &config, nil
}