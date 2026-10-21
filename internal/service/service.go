package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/bytemare/opaque"
	"github.com/example-git/haunt-sync/internal/protocol"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

//go:embed schema.sql
var schemaSQL string

type Service struct {
	Config   Config
	Pool     *pgxpool.Pool
	Opaque   *opaque.Server
	Mailer   Mailer
	requests chan struct{}
}

type APIError struct {
	Status int
	Code   string
}

func (e *APIError) Error() string           { return e.Code }
func problem(status int, code string) error { return &APIError{status, code} }

func New(ctx context.Context, config Config) (*Service, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	pc, err := pgxpool.ParseConfig(config.DatabaseURL)
	if err != nil {
		return nil, errors.New("invalid sync database configuration")
	}
	// Each bounded auth request can hold a transaction while inserting its
	// one-use proof through the pool. Leave capacity for those independent writes.
	pc.MaxConns = 32
	pc.ConnConfig.RuntimeParams["search_path"] = pgx.Identifier{config.Schema}.Sanitize() + ",pg_catalog"
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			pool.Close()
		}
	}()
	if _, err = pool.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS "+pgx.Identifier{config.Schema}.Sanitize()); err != nil {
		return nil, err
	}
	if _, err = pool.Exec(ctx, schemaSQL); err != nil {
		return nil, err
	}
	conf := protocol.Configuration()
	secret, public := conf.KeyGen()
	material := &opaque.ServerKeyMaterial{Identity: protocol.ServerIdentity(config.Issuer), PrivateKey: secret, PublicKeyBytes: public.Encode(), OPRFGlobalSeed: conf.GenerateOPRFSeed()}
	if _, err = pool.Exec(ctx, `INSERT INTO configuration(singleton,protocol,server_key_material) VALUES(true,$1,$2) ON CONFLICT(singleton) DO NOTHING`, protocol.Version, material.Encode()); err != nil {
		return nil, err
	}
	material.Flush()
	var name string
	var encoded []byte
	if err = pool.QueryRow(ctx, `SELECT protocol,server_key_material FROM configuration WHERE singleton`).Scan(&name, &encoded); err != nil {
		return nil, err
	}
	if name != protocol.Version {
		return nil, errors.New("sync protocol configuration does not match the saved installation")
	}
	material, err = conf.DecodeServerKeyMaterial(encoded)
	clear(encoded)
	if err != nil {
		return nil, err
	}
	if string(material.Identity) != string(protocol.ServerIdentity(config.Issuer)) {
		return nil, errors.New("sync issuer differs from the saved installation")
	}
	op, err := conf.Server()
	if err != nil {
		return nil, err
	}
	if err = op.SetKeyMaterial(material); err != nil {
		return nil, err
	}
	success = true
	s := &Service{Config: config, Pool: pool, Opaque: op, requests: make(chan struct{}, 16)}
	if config.SMTPHost != "" {
		s.Mailer = &SMTPMailer{Config: config}
	}
	return s, nil
}

func (s *Service) Close() { s.Opaque.ServerKeyMaterial.Flush(); s.Pool.Close() }
func randomID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func hash(value string) []byte { sum := sha256.Sum256([]byte(value)); return sum[:] }
func scope(origin string) string {
	return "server:" + base64.RawURLEncoding.EncodeToString(hash(origin))
}

func decode(w http.ResponseWriter, r *http.Request, out any, limit int64) error {
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		return problem(415, "json_required")
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return problem(400, "invalid_request")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return problem(400, "invalid_request")
	}
	return nil
}
func write(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}
func fail(w http.ResponseWriter, err error) {
	var e *APIError
	if errors.As(err, &e) {
		if e.Status == 429 {
			w.Header().Set("Retry-After", "60")
		}
		write(w, e.Status, map[string]string{"error": e.Code})
		return
	}
	write(w, 500, map[string]string{"error": "internal_error"})
}

type endpoint func(http.ResponseWriter, *http.Request) error

func (s *Service) route(mux *http.ServeMux, pattern string, handler endpoint) {
	mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		if err := handler(w, r); err != nil {
			fail(w, err)
		}
	})
}

func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	s.route(mux, "GET /healthz", func(w http.ResponseWriter, r *http.Request) error {
		if err := s.Pool.Ping(r.Context()); err != nil {
			return problem(503, "database_unavailable")
		}
		write(w, 200, map[string]string{"status": "ready"})
		return nil
	})
	s.route(mux, "GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) error {
		write(w, 200, map[string]any{"issuer": s.Config.Issuer, "authorization_endpoint": s.Config.Issuer + "/v1/oauth/authorize", "token_endpoint": s.Config.Issuer + "/v1/oauth/token", "revocation_endpoint": s.Config.Issuer + "/v1/devices/current", "response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code"}, "code_challenge_methods_supported": []string{"S256"}, "token_endpoint_auth_methods_supported": []string{"none"}, "dpop_signing_alg_values_supported": []string{"ES256"}})
		return nil
	})
	s.route(mux, "GET /v1/config", func(w http.ResponseWriter, r *http.Request) error {
		write(w, 200, map[string]any{"protocol": protocol.Version, "issuer": s.Config.Issuer, "server_identity": string(protocol.ServerIdentity(s.Config.Issuer)), "key_stretching": map[string]int{"iterations": 3, "memory": 65536, "parallelism": 4}, "max_backup_bytes": 32 << 20, "encryption_key_derivation": "password-keyword-argon2id-v1", "browser_authorization": "desktop-key-pairing-v1"})
		return nil
	})
	s.route(mux, "POST /v1/auth/register/start", s.registrationStart)
	s.route(mux, "POST /v1/auth/register/finish", s.registrationFinish)
	s.route(mux, "POST /v1/auth/login/start", s.loginStart)
	s.route(mux, "POST /v1/auth/login/finish", s.loginFinish)
	s.route(mux, "POST /v1/email/start", s.emailStart)
	s.route(mux, "POST /v1/email/verify", s.emailVerify)
	s.route(mux, "POST /v1/email/login", s.emailLogin)
	s.route(mux, "POST /v1/email/link", s.emailLink)
	s.route(mux, "POST /v1/recovery/start", s.recoveryStart)
	s.route(mux, "POST /v1/recovery/finish", s.recoveryFinish)
	s.route(mux, "GET /v1/vault/{scope}", s.vaultGet)
	s.route(mux, "GET /v1/vaults", s.vaultOrigins)
	s.route(mux, "PUT /v1/vault/{scope}", s.vaultPut)
	s.route(mux, "GET /v1/devices", s.devices)
	s.route(mux, "DELETE /v1/devices/{id}", s.revoke)
	s.route(mux, "POST /v1/oauth/authorize", s.authorizeStart)
	s.route(mux, "POST /v1/oauth/authorize/{id}/approve", s.authorizeApprove)
	s.route(mux, "POST /v1/oauth/token", s.exchangeCode)
	updates := updateHandler(s.Config.UpdatesDirectory)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		// Public release distribution has its own bounded streaming capacity and
		// never accepts sync credentials or occupies an authentication worker.
		if strings.HasPrefix(r.URL.Path, "/client-updates/") {
			updates.ServeHTTP(w, r)
			return
		}
		origin := r.Header.Get("Origin")
		if origin != "" {
			if !s.Config.trustedClient(origin) {
				if _, err := Origin(origin, s.Config.AllowLoopbackHTTP); err != nil {
					fail(w, problem(403, "untrusted_origin"))
					return
				}
				// Community pages can operate only delegated OAuth grants, vaults and logout.
				if !(strings.HasPrefix(r.URL.Path, "/v1/oauth/") || strings.HasPrefix(r.URL.Path, "/v1/vault/") || r.URL.Path == "/v1/devices/current") {
					fail(w, problem(403, "web_scope_required"))
					return
				}
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, DPoP")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		}
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		select {
		case s.requests <- struct{}{}:
			defer func() { <-s.requests }()
		default:
			fail(w, problem(503, "service_busy_retry_later"))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Service) rate(r *http.Request, operation string) error {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	current, parseErr := netip.ParseAddr(ip)
	if parseErr == nil {
		trusted := func(address netip.Addr) bool {
			for _, prefix := range s.Config.proxies {
				if prefix.Contains(address.Unmap()) {
					return true
				}
			}
			return false
		}
		if trusted(current) {
			chain := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
			for i := len(chain) - 1; i >= 0; i-- {
				if !trusted(current) {
					break
				}
				if strings.TrimSpace(chain[i]) == "" {
					break
				}
				next, e := netip.ParseAddr(strings.TrimSpace(chain[i]))
				if e != nil {
					return problem(400, "invalid_proxy_client_ip")
				}
				current = next.Unmap()
			}
		}
		ip = current.Unmap().String()
	}
	bucket := base64.RawURLEncoding.EncodeToString(hash(operation + "\x00" + ip))
	return s.rateBucket(r, bucket, 30)
}

func (s *Service) rateBucket(r *http.Request, bucket string, maximum int) error {
	var count int
	err := s.Pool.QueryRow(r.Context(), `INSERT INTO rate_limits(bucket,started_at,count) VALUES($1,clock_timestamp(),1)
 ON CONFLICT(bucket) DO UPDATE SET count=CASE WHEN rate_limits.started_at<clock_timestamp()-interval '60 seconds' THEN 1 ELSE rate_limits.count+1 END,
 started_at=CASE WHEN rate_limits.started_at<clock_timestamp()-interval '60 seconds' THEN clock_timestamp() ELSE rate_limits.started_at END RETURNING count`, bucket).Scan(&count)
	if err != nil {
		return err
	}
	if count > maximum {
		return problem(429, "rate_limited")
	}
	return nil
}

func (s *Service) Cleanup(ctx context.Context) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			for _, q := range []string{`DELETE FROM challenges WHERE expires_at<clock_timestamp()`, `DELETE FROM email_challenges WHERE expires_at<clock_timestamp()`, `DELETE FROM authorizations WHERE expires_at<clock_timestamp()`, `DELETE FROM proof_replays WHERE expires_at<clock_timestamp()`, `DELETE FROM rate_limits WHERE started_at<clock_timestamp()-interval '10 minutes'`} {
				s.Pool.Exec(ctx, q)
			}
		}
	}
}
