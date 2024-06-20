package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/joho/godotenv"

	"github.com/mloughton/chirpy/internal/server"
)

func main() {

	godotenv.Load()

	dbg := flag.Bool("debug", false, "Enable debug mode")
	flag.Parse()

	if *dbg {
		os.Remove("./database.json")
	}

	server, err := server.NewServer()
	if err != nil {
		panic(fmt.Sprintf("cannot create server: %s", err))
	}

	err = server.ListenAndServe()
	if err != nil {
		panic(fmt.Sprintf("cannot start server: %s", err))
	}
}
