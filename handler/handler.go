package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/SR-SHREYAS/network-security-scanner.git/schema"
	"github.com/SR-SHREYAS/network-security-scanner.git/service"
)

func HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func ScanPortHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		target = "127.0.0.1"
	}
	workers := 50
	if v := r.URL.Query().Get("workers"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			workers = n
		}
	}

	fmt.Println("=== Clinic Network Security Scanner ===")
	fmt.Printf("Target: %s\n", target)
	fmt.Printf("Ports : %d common ports\n", len(schema.CommonPorts))
	fmt.Printf("Workers: %d\n\n", workers)

	results := service.ScanPorts(target, workers)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(results); err != nil {
		http.Error(w, fmt.Sprintf("Error encoding results: %v", err), http.StatusInternalServerError)
	}
}
