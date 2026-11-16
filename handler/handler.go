package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/SR-SHREYAS/network-security-scanner.git/config"
	"github.com/SR-SHREYAS/network-security-scanner.git/service"
)

func HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// func ScanPortHandler(w http.ResponseWriter, r *http.Request) {
// 	target := r.URL.Query().Get("target")
// 	if target == "" {
// 		target = "127.0.0.1"
// 	}

// 	workers := 50
// 	if v := r.URL.Query().Get("workers"); v != "" {
// 		if n, err := strconv.Atoi(v); err == nil && n > 0 {
// 			workers = n
// 		}
// 	}

// 	fmt.Println("=== Clinic Network Security Scanner ===")
// 	fmt.Printf("Target: %s\n", target)
// 	fmt.Printf("Ports : %d common ports\n", len(schema.CommonPorts))
// 	fmt.Printf("Workers: %d\n\n", workers)

// 	results, err := service.ScanPorts(r.Context(), target, workers)
// 	if err != nil {
// 		if errors.Is(err, service.ErrInvalidTarget) {
// 			http.Error(w, err.Error(), http.StatusBadRequest)
// 			return
// 		}
// 		http.Error(w, "scan failed", http.StatusInternalServerError)
// 		return
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	if err := json.NewEncoder(w).Encode(results); err != nil {
// 		http.Error(w, fmt.Sprintf("Error encoding results: %v", err), http.StatusInternalServerError)
// 	}
// }

type ScanHandler struct {
	scanner *service.Scanner
	cfg     config.Config
}

func NewScanHandler(s *service.Scanner, cfg config.Config) *ScanHandler {
	return &ScanHandler{scanner: s, cfg: cfg}
}

func (h *ScanHandler) Scan(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	target := q.Get("target")
	if target == "" {
		target = "127.0.0.1"
	}

	workers := h.cfg.DefaultWorkers
	if v := q.Get("workers"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > h.cfg.MaxWorkers {
			http.Error(w, fmt.Sprintf("workers must be an integer between 1 and %d", h.cfg.MaxWorkers),
				http.StatusBadRequest)
			return
		}
		workers = n
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.cfg.ScanTimeout)
	defer cancel()

	report, err := h.scanner.Scan(ctx, target, workers)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidTarget):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case errors.Is(err, context.DeadlineExceeded):
			http.Error(w, "scan timed out", http.StatusGatewayTimeout)
		case errors.Is(err, context.Canceled):
			// client disconnected; nobody is listening
		default:
			http.Error(w, "scan failed", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(report); err != nil {
		http.Error(w, "failed to encode report", http.StatusInternalServerError)
	}
}
