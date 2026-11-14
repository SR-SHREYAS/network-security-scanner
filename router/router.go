package router

import (
	"net/http"

	"github.com/SR-SHREYAS/network-security-scanner.git/handler"
)

func RegisterRoutes() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", handler.HealthCheckHandler)
	mux.HandleFunc("/scan", handler.ScanPortHandler)
	return mux
}
