package service

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestTrustedStandaloneClientOrigins(t *testing.T) {
	config := Config{Issuer: "https://sync.example.test", DatabaseURL: "postgres://fixture", TrustedClientOrigins: "https://client.example.test"}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	service := &Service{Config: config, requests: make(chan struct{}, 1)}
	handler := service.Handler()
	for _, test := range []struct {
		origin, path string
		status       int
	}{
		{"https://client.example.test", "/v1/auth/login/start", 204},
		{"https://app.chatxo.local", "/v1/auth/login/start", 204},
		{"https://other.example.test", "/v1/auth/login/start", 403},
		{"https://client.example.test.evil.test", "/v1/auth/login/start", 403},
		{"https://other.example.test", "/v1/oauth/token", 204},
	} {
		request := httptest.NewRequest(http.MethodOptions, test.path, nil)
		request.Header.Set("Origin", test.origin)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.status {
			t.Fatalf("%s %s: %d", test.origin, test.path, response.Code)
		}
		if test.status == 204 && response.Header().Get("Access-Control-Allow-Origin") != test.origin {
			t.Fatal("origin not preserved")
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/config", nil)
	request.Header.Set("Origin", "https://client.example.test")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 200 {
		t.Fatalf("trusted request did not reach configuration handler: %d", response.Code)
	}
}

func TestActionsHostedClientOrigin(t *testing.T) {
	if expected := os.Getenv("HAUNT_WEB_CLIENT_ORIGIN"); expected != "" && HostedClientOrigin != expected {
		t.Fatal("Actions build omitted the hosted client origin")
	}
}

func TestBuiltInWebClientOrigin(t *testing.T) {
	previous := HostedClientOrigin
	t.Cleanup(func() { HostedClientOrigin = previous })
	HostedClientOrigin = "https://hosted.example.test"
	config := Config{Issuer: "https://sync.example.test", DatabaseURL: "postgres://fixture"}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	if !config.trustedClient(HostedClientOrigin) || !config.trustedClient("https://app.chatxo.local") || config.trustedClient("https://other.example.test") {
		t.Fatal("incorrect built-in client trust")
	}
	HostedClientOrigin = "https://hosted.example.test/path"
	if err := config.Validate(); err == nil {
		t.Fatal("invalid built-in origin accepted")
	}
}

func TestRejectInvalidTrustedClientOrigins(t *testing.T) {
	for _, value := range []string{"*", "https://*.example.test", "http://client.example.test", "https://client.example.test/path", "https://client.example.test,"} {
		config := Config{Issuer: "https://sync.example.test", DatabaseURL: "postgres://fixture", TrustedClientOrigins: value}
		if err := config.Validate(); err == nil {
			t.Fatalf("accepted invalid trusted origin %q", value)
		}
	}
}
