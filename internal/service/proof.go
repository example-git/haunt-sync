package service

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
var proofID = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

func proofKey(raw json.RawMessage) (*jose.JSONWebKey, string, error) {
	if len(raw) > 1024 {
		return nil, "", problem(400, "invalid_proof_key")
	}
	var key jose.JSONWebKey
	if json.Unmarshal(raw, &key) != nil || !key.IsPublic() || !key.Valid() {
		return nil, "", problem(400, "invalid_proof_key")
	}
	public, ok := key.Key.(*ecdsa.PublicKey)
	if !ok || public.Curve != elliptic.P256() {
		return nil, "", problem(400, "invalid_proof_key")
	}
	thumb, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, "", problem(400, "invalid_proof_key")
	}
	return &key, base64.RawURLEncoding.EncodeToString(thumb), nil
}

type proofClaims struct {
	ID        string `json:"jti"`
	Method    string `json:"htm"`
	URL       string `json:"htu"`
	IssuedAt  int64  `json:"iat"`
	TokenHash string `json:"ath,omitempty"`
}

func (s *Service) verifyProof(r *http.Request, expectedThumb, token string) error {
	raw := r.Header.Get("DPoP")
	if len(raw) > 8192 || strings.Count(raw, ".") != 2 {
		return problem(401, "invalid_dpop_proof")
	}
	signed, err := jose.ParseSignedCompact(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil || len(signed.Signatures) != 1 {
		return problem(401, "invalid_dpop_proof")
	}
	header := signed.Signatures[0].Protected
	if header.ExtraHeaders[jose.HeaderType] != "dpop+jwt" || header.JSONWebKey == nil {
		return problem(401, "invalid_dpop_proof")
	}
	public, err := json.Marshal(header.JSONWebKey)
	if err != nil {
		return problem(401, "invalid_dpop_proof")
	}
	key, thumb, err := proofKey(public)
	if err != nil || thumb != expectedThumb {
		return problem(401, "proof_key_mismatch")
	}
	payload, err := signed.Verify(key.Key)
	if err != nil {
		return problem(401, "invalid_dpop_proof")
	}
	var claims proofClaims
	if json.Unmarshal(payload, &claims) != nil || !proofID.MatchString(claims.ID) || claims.Method != r.Method || claims.URL != s.Config.Issuer+r.URL.EscapedPath() || claims.IssuedAt < time.Now().Unix()-90 || claims.IssuedAt > time.Now().Unix()+30 {
		return problem(401, "invalid_dpop_proof")
	}
	if (token != "" && claims.TokenHash != base64.RawURLEncoding.EncodeToString(hash(token))) || (token == "" && claims.TokenHash != "") {
		return problem(401, "token_binding_mismatch")
	}
	tag, err := s.Pool.Exec(r.Context(), `INSERT INTO proof_replays(thumbprint,jti,expires_at) VALUES($1,$2,clock_timestamp()+interval '2 minutes') ON CONFLICT DO NOTHING`, thumb, claims.ID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return problem(401, "replayed_proof")
	}
	return nil
}

type Device struct {
	ID         string    `json:"id"`
	AccountID  string    `json:"-"`
	Thumbprint string    `json:"-"`
	Name       string    `json:"name"`
	Scope      string    `json:"scope"`
	Origin     string    `json:"origin"`
	CreatedAt  time.Time `json:"created_at"`
}

func (s *Service) authenticate(r *http.Request) (Device, error) {
	var device Device
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 || parts[0] != "DPoP" || !identifier.MatchString(parts[1]) {
		return device, problem(401, "authentication_required")
	}
	err := s.Pool.QueryRow(r.Context(), `SELECT id,account_id,thumbprint,name,scope,origin,created_at FROM devices WHERE token_hash=$1 AND revoked_at IS NULL`, hash(parts[1])).Scan(&device.ID, &device.AccountID, &device.Thumbprint, &device.Name, &device.Scope, &device.Origin, &device.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return device, problem(401, "session_revoked")
	}
	if err != nil {
		return device, err
	}
	if err = s.verifyProof(r, device.Thumbprint, parts[1]); err != nil {
		return device, err
	}
	requestOrigin := r.Header.Get("Origin")
	if strings.HasPrefix(device.Scope, "server:") && requestOrigin != "" && requestOrigin != device.Origin {
		return device, problem(403, "origin_scope_mismatch")
	}
	if (device.Scope == "full" || device.Scope == "email") && requestOrigin != "" && requestOrigin != "https://app.chatxo.local" {
		return device, problem(403, "web_scope_required")
	}
	return device, nil
}

func (s *Service) devices(w http.ResponseWriter, r *http.Request) error {
	current, err := s.authenticate(r)
	if err != nil {
		return err
	}
	if current.Scope != "full" {
		return problem(403, "full_scope_required")
	}
	rows, err := s.Pool.Query(r.Context(), `SELECT id,name,scope,origin,created_at FROM devices WHERE account_id=$1 AND revoked_at IS NULL ORDER BY created_at,id`, current.AccountID)
	if err != nil {
		return err
	}
	defer rows.Close()
	items := []Device{}
	for rows.Next() {
		var item Device
		if err = rows.Scan(&item.ID, &item.Name, &item.Scope, &item.Origin, &item.CreatedAt); err != nil {
			return err
		}
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		return err
	}
	write(w, 200, map[string]any{"devices": items, "current": current.ID})
	return nil
}

func (s *Service) revoke(w http.ResponseWriter, r *http.Request) error {
	current, err := s.authenticate(r)
	if err != nil {
		return err
	}
	id := r.PathValue("id")
	if id == "current" {
		id = current.ID
	}
	if current.Scope != "full" && id != current.ID {
		return problem(403, "full_scope_required")
	}
	tag, err := s.Pool.Exec(r.Context(), `UPDATE devices SET revoked_at=clock_timestamp() WHERE account_id=$1 AND id=$2 AND revoked_at IS NULL`, current.AccountID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return problem(404, "device_not_found")
	}
	w.WriteHeader(204)
	return nil
}
