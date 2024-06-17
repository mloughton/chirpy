package main

import (
	"fmt"
	"log"
	"net/http"
	"text/template"
)

type apiConfig struct {
	fileserverHits int
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits++
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) HandleGetMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("Hits: %d", cfg.fileserverHits)))
}

func (cfg *apiConfig) HandleResetMetrics(w http.ResponseWriter, r *http.Request) {
	cfg.fileserverHits = 0
	w.WriteHeader(http.StatusOK)
}

func appHandler() http.Handler {
	return http.StripPrefix("/app", http.FileServer(http.Dir(".")))
}

func (cfg *apiConfig) HandleGetAdminMetrics(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("./admin/metrics/index.html")
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	err = tmpl.Execute(w, cfg.fileserverHits)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Println(err)
		return
	}
}

func main() {
	mux := http.NewServeMux()
	apiCfg := &apiConfig{}

	mux.Handle("/app/*", apiCfg.middlewareMetricsInc(appHandler()))

	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	mux.HandleFunc("GET /api/metrics", apiCfg.HandleGetMetrics)
	mux.HandleFunc("/api/reset", apiCfg.HandleResetMetrics)

	mux.HandleFunc("GET /admin/metrics/", apiCfg.HandleGetAdminMetrics)

	server := &http.Server{
		Handler: mux,
		Addr:    "localhost:8080",
	}

	log.Printf("listening and serving on %s : open using http://localhost:8080/app", server.Addr)
	server.ListenAndServe()
}
