package main

import (
	"context"
	"flag"
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
		addr      = flag.String("addr", "127.0.0.1:8089", "Address to listen on")
		accountID = flag.String("account-id", "111122223333", "AWS account ID to use")
		region    = flag.String("region", "eu-west-2", "AWS region to use")
		// AWS doesn't really document a delay, starting at 1s to be long enough to trigger the need for a retry, not long
		// enough to be annoying in dev. Can adjust later with real-world data
		certIssueDelay = flag.Duration("issue-delay", 1*time.Second, "How long after an issue call a certificate is ready for Get")
	)
	flag.Parse()

	svr := &server{
		accountID:      *accountID,
		region:         *region,
		certIssueDelay: *certIssueDelay,
	}

	server := &http.Server{
		Addr:    *addr,
		Handler: svr,
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
