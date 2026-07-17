package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ersinkoc/monopam/internal/service"
)

const shutdownTimeout = 10 * time.Second

func main() {
	if err := run(); err != nil {
		slog.Error("monopam stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	addr := flag.String("addr", envOrDefault("MONOPAM_ADDR", "127.0.0.1:8080"), "HTTP listen address")
	recordsPath := flag.String("records", envOrDefault("MONOPAM_RECORDS", "records.json"), "path to JSON records file")
	apiTokenFlag := flag.String("api-token", "", "resolve API bearer token (prefer MONOPAM_API_TOKEN)")
	flag.Parse()

	apiToken := *apiTokenFlag
	if apiToken == "" {
		apiToken = os.Getenv("MONOPAM_API_TOKEN")
	}
	if apiToken == "" {
		return errors.New("API token is required (set MONOPAM_API_TOKEN or -api-token)")
	}

	store, err := service.LoadStore(*recordsPath)
	if err != nil {
		return fmt.Errorf("load records: %w", err)
	}
	handler, err := service.NewHandler(apiToken, store)
	if err != nil {
		return fmt.Errorf("configure HTTP handler: %w", err)
	}

	server := &http.Server{
		Addr:              *addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() {
		slog.Info("monopam listening", "address", *addr, "records", *recordsPath)
		serveErr <- server.ListenAndServe()
	}()

	select {
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve HTTP: %w", err)
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		_ = server.Close()
		return fmt.Errorf("graceful shutdown: %w", err)
	}

	if err := <-serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve HTTP: %w", err)
	}
	return nil
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
