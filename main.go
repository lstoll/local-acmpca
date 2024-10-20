package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
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
		state          = flag.String("state", "", "Path to file to store JSON working state in. If empty, temp dir will be used")
		seed           = flag.String("seed", "", "Path to file to use to seed the store with")
		skipSeedUpdate = flag.Bool("skip-seed-update", false, "Do not update the seed file with generated certs")
	)
	flag.VisitAll(func(f *flag.Flag) {
		k := strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		if v := os.Getenv("LOCAL_ACMPCA_" + k); v != "" {
			if err := f.Value.Set(v); err != nil {
				panic(err)
			}
		}
	})
	flag.Parse()

	var (
		cleanState bool
		statePath  string = *state
	)
	if statePath == "" {
		sp, err := os.CreateTemp("", "local-acmpca-state*.json")
		if err != nil {
			slog.Error("failed to create state file", "err", err)
			os.Exit(1)
		}
		statePath = sp.Name()
		_ = sp.Close()
		_ = os.Remove(statePath)
		cleanState = true
	}

	slog.Info("Load/create state", "path", statePath)
	db, err := loadDB(statePath)
	if err != nil {
		slog.Error("failed to load/create state", "err", err)
		os.Exit(1)
	}

	if *seed != "" {
		slog.Info("Seeding state", "path", *seed)
		if err := loadAndSeed(*seed, db, *skipSeedUpdate); err != nil {
			slog.Error("failed to load/open state", "err", err)
			os.Exit(1)
		}
	}

	svr := &server{
		accountID:      *accountID,
		region:         *region,
		certIssueDelay: *certIssueDelay,

		db: db,
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

	if cleanState {
		slog.Info("Removing temporary state file", "path", statePath)
		_ = os.Remove(statePath)
	}

	log.Println("Server stopped")
}
