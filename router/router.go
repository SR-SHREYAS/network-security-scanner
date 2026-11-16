package router

import (
	"net/http"

	"github.com/SR-SHREYAS/network-security-scanner.git/handler"
)

func RegisterRoutes(scan *handler.ScanHandler) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", handler.HealthCheckHandler)
	mux.HandleFunc("GET /scan", scan.Scan)
	return mux
}
