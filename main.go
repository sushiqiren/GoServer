package main

import (
	"log"
	"net/http"
)

func main() {
	// Create a new ServeMux
	mux := http.NewServeMux()

	// Use http.FileServer as the handler for the root path
	fileServer := http.FileServer(http.Dir("."))

	// Add the handler for the root path
	mux.Handle("/", fileServer)

	// Create a new Server
	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	// Start the server
	log.Println("Starting server on :8080")
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
