package server

import (
	"net/http"
	"os"

	"github.com/mloughton/chirpy/internal/database"
)

type Server struct {
	db             *database.DB
	jwtSecret      string
	polkaAPIKey    string
	fileserverHits int
}

func NewServer() (*http.Server, error) {
	db, err := database.NewDB("./database.json")
	if err != nil {
		return nil, err
	}

	NewServer := &Server{
		db:          db,
		jwtSecret:   os.Getenv("JWT_SECRET"),
		polkaAPIKey: os.Getenv("POLKA_API_KEY"),
	}

	server := &http.Server{
		Addr:    "localhost:8080",
		Handler: NewServer.RegisterRoutes(),
	}
	return server, nil
}
