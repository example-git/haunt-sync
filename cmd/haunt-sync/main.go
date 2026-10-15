package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/example-git/haunt-sync/internal/service"
)

var version = "development"

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		log.Print("Haunt Sync ", version)
		return
	}
	config := service.Config{Issuer: os.Getenv("HAUNT_SYNC_ISSUER"), DatabaseURL: os.Getenv("HAUNT_SYNC_DATABASE_URL"), Schema: os.Getenv("HAUNT_SYNC_SCHEMA"), AllowLoopbackHTTP: os.Getenv("HAUNT_SYNC_ALLOW_LOOPBACK_HTTP") == "true", SMTPHost: os.Getenv("HAUNT_SYNC_SMTP_HOST"), SMTPPort: os.Getenv("HAUNT_SYNC_SMTP_PORT"), SMTPUsername: os.Getenv("HAUNT_SYNC_SMTP_USERNAME"), SMTPPassword: os.Getenv("HAUNT_SYNC_SMTP_PASSWORD"), SMTPCAFile: os.Getenv("HAUNT_SYNC_SMTP_CA_FILE"), MailFrom: os.Getenv("HAUNT_SYNC_MAIL_FROM"), TrustedProxies: os.Getenv("HAUNT_SYNC_TRUSTED_PROXIES")}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	config.UpdatesDirectory = os.Getenv("HAUNT_SYNC_UPDATES_DIR")
	defer cancel()
	initial, done := context.WithTimeout(ctx, 30*time.Second)
	s, err := service.New(initial, config)
	done()
	if err != nil {
		log.Fatal("sync initialization: ", err)
	}
	defer s.Close()
	address := os.Getenv("HAUNT_SYNC_LISTEN_ADDR")
	if address == "" {
		address = "127.0.0.1:8090"
	}
	cert, key := os.Getenv("HAUNT_SYNC_TLS_CERT"), os.Getenv("HAUNT_SYNC_TLS_KEY")
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		log.Fatal("invalid listen address")
	}
	ip := net.ParseIP(host)
	if (cert == "") != (key == "") {
		log.Fatal("both TLS certificate and key are required")
	}
	if cert == "" && (ip == nil || !ip.IsLoopback()) {
		log.Fatal("plaintext listener must be loopback; supply TLS certificate/key for an external listener")
	}
	server := &http.Server{Addr: address, Handler: s.Handler(), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 45 * time.Second, WriteTimeout: 45 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	cleaned := make(chan struct{})
	go func() { defer close(cleaned); s.Cleanup(ctx) }()
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		<-ctx.Done()
		shutdown, stop := context.WithTimeout(context.Background(), 50*time.Second)
		defer stop()
		server.Shutdown(shutdown)
	}()
	log.Printf("Haunt Sync listening on %s", address)
	if cert != "" {
		err = server.ListenAndServeTLS(cert, key)
	} else {
		err = server.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal("sync listener: ", err)
	}
	if errors.Is(err, http.ErrServerClosed) {
		<-stopped
		<-cleaned
	}
}
