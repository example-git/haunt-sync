package service

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
)

type capturedMail struct {
	mu    sync.Mutex
	links []string
}

func (m *capturedMail) Send(_ context.Context, _ string, link string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.links = append(m.links, link)
	return nil
}

func TestBrowserProtocol(t *testing.T) {
	database := os.Getenv("HAUNT_SYNC_TEST_DATABASE_URL")
	if database == "" {
		t.Skip("set HAUNT_SYNC_TEST_DATABASE_URL to the isolated fixture database")
	}
	parsed, err := pgx.ParseConfig(database)
	if err != nil {
		t.Fatal("invalid fixture configuration")
	}
	if parsed.Host != "127.0.0.1" || parsed.Port != 32768 || parsed.Database != "haunt_sync_iteration" {
		t.Fatal("fixture must be the dedicated chatxo-identity-check sync database")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	issuer := "http://" + listener.Addr().String()
	schema := "sync_test_" + base32ForTest(randomID())[:16]
	s, err := New(t.Context(), Config{Issuer: issuer, DatabaseURL: database, Schema: schema, AllowLoopbackHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer s.Pool.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
	mailbox := &capturedMail{}
	s.Mailer = mailbox
	mux := http.NewServeMux()
	mux.Handle("/", s.Handler())
	mux.HandleFunc("GET /test/mail", func(w http.ResponseWriter, r *http.Request) {
		mailbox.mu.Lock()
		defer mailbox.mu.Unlock()
		json.NewEncoder(w).Encode(mailbox.links)
	})
	mux.HandleFunc("POST /test/age", func(w http.ResponseWriter, r *http.Request) {
		if _, err := s.Pool.Exec(r.Context(), `UPDATE devices SET created_at=clock_timestamp()-interval '5 years'`); err != nil {
			t.Error(err)
		}
		w.WriteHeader(204)
	})
	mux.HandleFunc("GET /test/plaintext", func(w http.ResponseWriter, r *http.Request) {
		var found bool
		err := s.Pool.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM vaults WHERE ciphertext::text LIKE '%synthetic-community-secret%' OR ciphertext::text LIKE '%correct master password%' OR ciphertext::text LIKE '%synthetic private sync keyword%')`).Scan(&found)
		if err != nil {
			t.Error(err)
		}
		json.NewEncoder(w).Encode(map[string]bool{"found": found})
	})
	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	defer server.Close()
	client := os.Getenv("HAUNT_SYNC_CLIENT_CHECKOUT")
	if client == "" {
		client, err = filepath.Abs("../../../client")
		if err != nil {
			t.Fatal(err)
		}
	}
	files := []string{"tests/sync-integration.test.ts", "tests/sync-secret-change.test.ts", "tests/sync-archive-scale.test.ts", "tests/sync-ui.test.ts"}
	if selected := os.Getenv("HAUNT_SYNC_TEST_FILE"); selected != "" {
		found := false
		for _, file := range files {
			if file == selected {
				found = true
			}
		}
		if !found {
			t.Fatal("HAUNT_SYNC_TEST_FILE must name a supported sync test file")
		}
		files = []string{selected}
	}
	for _, file := range files {
		// Independent scenarios get a fresh test-only rate counter. The production
		// limit is unchanged and remains active throughout each complete scenario.
		if _, err = s.Pool.Exec(t.Context(), `DELETE FROM rate_limits`); err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(t.Context(), "npm", "exec", "--", "vitest", "run", file, "--maxWorkers=1")
		command.Dir = client
		command.Env = append(os.Environ(), "HAUNT_SYNC_TEST_ISSUER="+issuer, "HAUNT_SYNC_TEST_PORTAL="+issuer)
		output, err := command.CombinedOutput()
		t.Log(string(output))
		if err != nil {
			t.Fatal("client/Go HTTP integration failed")
		}
	}

}
func base32ForTest(value string) string {
	out := []byte(value)
	for i, b := range out {
		out[i] = 'a' + b%26
	}
	return string(out)
}
