package main

import (
	"fmt"
	"log"
	"net/http"
)

type apiConfig struct {
	filserverHits int
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.filserverHits++
		next.ServeHTTP(w, r)
	})
}

func middlewareLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) HandleGetMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("Hits: %d", cfg.filserverHits)))
}

func (cfg *apiConfig) HandleResetMetrics(w http.ResponseWriter, r *http.Request) {
	cfg.filserverHits = 0
	w.WriteHeader(http.StatusOK)
}

func appHandler() http.Handler {
	return http.StripPrefix("/app", http.FileServer(http.Dir(".")))
}

func main() {
	mux := http.NewServeMux()
	apiCfg := &apiConfig{}

	mux.Handle("/app/*", apiCfg.middlewareMetricsInc(appHandler()))

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	mux.HandleFunc("/metrics", apiCfg.HandleGetMetrics)
	mux.HandleFunc("/reset", apiCfg.HandleResetMetrics)

	server := &http.Server{
		Handler: mux,
		Addr:    "localhost:8080",
	}

	log.Printf("listening and serving on %s : open using http://localhost:8080/app", server.Addr)
	server.ListenAndServe()
}
