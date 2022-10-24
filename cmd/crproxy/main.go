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
	cli := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 10 {
				return http.ErrUseLastResponse
			}
			s := make([]string, 0, len(via)+1)
			for _, v := range via {
				s = append(s, v.URL.String())
			}
			s = append(s, req.URL.String())
			logger.Println("redirect", s)
			return nil
		},
	}

	crp := crproxy.NewCRProxy(
		crproxy.WithBaseClient(cli),
		crproxy.WithLogger(logger),
	)
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
