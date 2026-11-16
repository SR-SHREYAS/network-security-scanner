package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/SR-SHREYAS/network-security-scanner.git/config"
	"github.com/SR-SHREYAS/network-security-scanner.git/handler"
	"github.com/SR-SHREYAS/network-security-scanner.git/router"
	"github.com/SR-SHREYAS/network-security-scanner.git/service"
)

func main() {
	cfg := config.Load()

	scanner := service.NewScanner(cfg)
	scanHandler := handler.NewScanHandler(scanner, cfg)

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           router.RegisterRoutes(scanHandler),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      cfg.ScanTimeout + 5*time.Second, // must outlast the longest scan
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Printf("listening on %s", cfg.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()

	// Graceful shutdown: let in-flight scans finish on Ctrl+C / SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ScanTimeout+5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown: %v", err)
	}
}
