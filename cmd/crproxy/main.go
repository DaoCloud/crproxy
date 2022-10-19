package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/gorilla/handlers"
	"github.com/wzshiming/crproxy"
)

var address string

func init() {
	flag.StringVar(&address, "a", ":8080", "listen on the address")
	flag.Parse()
}

func main() {
	ctx := context.Background()
	logger := log.New(os.Stderr, "[cr proxy] ", log.LstdFlags)

	mux := http.NewServeMux()

	crp := crproxy.NewCRProxy(http.DefaultClient, logger)
	mux.Handle("/v2/", crp)
	server := http.Server{
		BaseContext: func(listener net.Listener) context.Context {
			return ctx
		},
		Handler: handlers.LoggingHandler(os.Stderr, mux),
		Addr:    address,
	}

	err := server.ListenAndServe()
	if err != nil {
		logger.Println("failed to ListenAndServe:", err)
		os.Exit(1)
	}
}
