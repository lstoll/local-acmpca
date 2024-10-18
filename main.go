package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"golang.org/x/sys/unix"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, unix.SIGTERM)
	defer stop()

	var (
		addr = flag.String("addr", "127.0.0.1:8089", "Address to listen on")
	)
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("got req: %#v", r)
		fmt.Fprintln(w, "OK")
	})

	server := &http.Server{
		Addr:    *addr,
		Handler: mux,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Could not listen on :8080: %v\n", err)
		}
		log.Println("Done")
	}()
	log.Printf("Server is ready to handle requests at %s", *addr)

	<-ctx.Done()
	log.Println("Shutting down the server...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Could not gracefully shut down the server: %v\n", err)
	}
	log.Println("Server stopped")
}
