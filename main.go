package main

import (
    "net/http"
    "log"
)

func main() {
    // Create a new ServeMux
    mux := http.NewServeMux()

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