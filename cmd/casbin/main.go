package main

import (
	"log"
	"log/slog"
	"net/http"

	"manaty226/authzen-interop-pdp-casbin/server"
)

func main() {
	service := NewCasbinHandler()
	s, err := server.NewServer(service)
	if err != nil {
		log.Fatalln(err)
	}
	slog.Info("Server started at http://localhost:8080")
	if err := http.ListenAndServe(":8080", s); err != nil {
		log.Fatalln(err)
	}
}
