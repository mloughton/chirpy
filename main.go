package main

import "net/http"

func main() {

	server := http.Server{
		Handler: http.NewServeMux(),
		Addr:    "localhost:8080",
	}

	server.ListenAndServe()
}
