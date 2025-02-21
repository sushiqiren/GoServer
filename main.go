package main

import (
	"log"
	"net/http"
	"strconv"
	"sync/atomic"
)

type apiConfig struct {
	fileserverHits atomic.Int32
}

func (a *apiConfig) incrementHitsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (a *apiConfig) hitsHandler(w http.ResponseWriter, r *http.Request) {
	hits := a.fileserverHits.Load()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hits: " + strconv.Itoa(int(hits))))
}

func (a *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	a.fileserverHits.Store(0)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hits counter reset"))
}

func main() {
	// Create a new ServeMux
	mux := http.NewServeMux()

	// Add the readiness endpoint
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Create an instance of apiConfig
	apiCfg := &apiConfig{}

	// Add the hits endpoint
	mux.HandleFunc("/hits", apiCfg.hitsHandler)

	// Add the metrics endpoint
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		apiCfg.hitsHandler(w, r)
	})

	// Add the reset endpoint
	mux.HandleFunc("/reset", apiCfg.resetHandler)

	// Use http.FileServer as the handler for the /app/ path
	fileServer := http.FileServer(http.Dir("."))

	// Add the handler for the /app/ path with the middleware
	appHandler := http.StripPrefix("/app", fileServer)
	mux.Handle("/app/", apiCfg.incrementHitsMiddleware(appHandler))

	// Add the handler for the /assets/ path with the middleware
	assetsHandler := http.StripPrefix("/assets/", http.FileServer(http.Dir("./assets")))
	mux.Handle("/assets/", apiCfg.incrementHitsMiddleware(assetsHandler))

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
