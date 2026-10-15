package service

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestPublicUpdatesProductionHandler(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "client-v0.5.0"), 0700); err != nil {
		t.Fatal(err)
	}
	asset := []byte("synthetic signed release")
	digest := sha256.Sum256(asset)
	entry := releaseArtifact{File: "Haunt.asar", Size: int64(len(asset)), SHA256: hex.EncodeToString(digest[:])}
	payload := releasePayload{Version: "0.5.0", Targets: map[string]struct {
		ASAR      releaseArtifact `json:"asar"`
		Installer releaseArtifact `json:"installer"`
	}{}}
	for _, target := range []string{"win32-x64", "linux-x64", "linux-arm64", "darwin-arm64"} {
		payload.Targets[target] = struct {
			ASAR      releaseArtifact `json:"asar"`
			Installer releaseArtifact `json:"installer"`
		}{entry, entry}
	}
	encoded, _ := json.Marshal(payload)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	signature := ed25519.Sign(key, encoded)
	manifest, _ := json.Marshal(map[string]any{"schema": 1, "payload": base64.StdEncoding.EncodeToString(encoded), "signature": base64.StdEncoding.EncodeToString(signature)})
	for _, path := range []string{"haunt-updates.json", "client-v0.5.0/haunt-updates.json"} {
		if err := os.WriteFile(filepath.Join(dir, path), manifest, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "client-v0.5.0/Haunt.asar"), asset, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "private.txt"), []byte("must not be served"), 0600); err != nil {
		t.Fatal(err)
	}
	// No pool and no auth workers: these requests use the actual production
	// wrapper and must not depend on a sync login or database connection.
	s := &Service{Config: Config{UpdatesDirectory: dir}}
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	request := func(method, path, rangeHeader string, code int) []byte {
		t.Helper()
		req, _ := http.NewRequest(method, server.URL+path, nil)
		req.Header.Set("Origin", "https://community.example.test")
		if rangeHeader != "" {
			req.Header.Set("Range", rangeHeader)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		if res.StatusCode != code {
			t.Fatalf("%s %s: %d %s", method, path, res.StatusCode, body)
		}
		if res.Header.Get("Access-Control-Allow-Origin") != "*" {
			t.Fatal("public feed CORS missing")
		}
		return body
	}
	body := request("GET", "/client-updates/haunt-updates.json?version=0.1.0&target=linux-x64", "", 200)
	if string(body) != string(manifest) || !ed25519.Verify(pub, encoded, signature) {
		t.Fatal("signed manifest altered")
	}
	if string(request("GET", "/client-updates/client-v0.5.0/Haunt.asar", "bytes=0-8", 206)) != string(asset[:9]) {
		t.Fatal("range download differs")
	}
	if len(request("HEAD", "/client-updates/client-v0.5.0/Haunt.asar", "", 200)) != 0 {
		t.Fatal("HEAD sent a body")
	}
	for _, path := range []string{"private.txt", "client-v0.5.0/private.txt", "client-v0.5.1/Haunt.asar", "client-v0.5.0/../../private.txt"} {
		request("GET", "/client-updates/"+path, "", 404)
	}
	request("POST", "/client-updates/haunt-updates.json", "", 405)
	if err := os.WriteFile(filepath.Join(dir, "client-v0.5.0/Haunt.asar"), []byte("truncated"), 0600); err != nil {
		t.Fatal(err)
	}
	request("GET", "/client-updates/client-v0.5.0/Haunt.asar", "", 404)
}
