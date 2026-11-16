package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Addr           string
	DefaultWorkers int
	MaxWorkers     int
	DialTimeout    time.Duration
	BannerTimeout  time.Duration
	ScanTimeout    time.Duration // hard cap for whole scan request
}

func Load() Config {
	return Config{
		Addr:           getEnv("SCANNER_ADDR", "127.0.0.1:8080"),
		DefaultWorkers: getInt("SCANNER_DEFAULT_WORKERS", 50),
		MaxWorkers:     getInt("SCANNER_MAX_WORKERS", 200),
		DialTimeout:    getDuration("SCANNER_DIAL_TIMEOUT", 2*time.Second),
		BannerTimeout:  getDuration("SCANNER_BANNER_TIMEOUT", 3*time.Second),
		ScanTimeout:    getDuration("SCANNER_SCAN_TIMEOUT", 30*time.Second),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return fallback
}

func getDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return fallback
}
