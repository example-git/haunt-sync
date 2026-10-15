package service

import "testing"

func TestIndependentSyncConfiguration(t *testing.T) {
	config := Config{Issuer: "https://friends.example.test", DatabaseURL: "postgres://fixture"}
	if err := config.Validate(); err != nil {
		t.Fatalf("independent sync instance requires no other authentication host: %v", err)
	}
	config.Issuer = "http://untrusted.example.test"
	if err := config.Validate(); err == nil {
		t.Fatal("explicit invalid origins must fail rather than switch to a fallback")
	}
}
