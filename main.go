package main

import (
	"fmt"
	"net/http"

	"github.com/SR-SHREYAS/network-security-scanner.git/router"
)

func main() {

	mux := router.RegisterRoutes()

	port := 8080

	server := http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	if err := server.ListenAndServe(); err != nil {
		panic(err)
	}

}
