package service

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"net/http"
	"net/url"
	"strings"
)

// The browser copies this canonical public-key request to its trusted desktop.
// Desktop validates it independently of storage-service responses.
type AuthorizationRequest struct {
	ClientID            string          `json:"client_id"`
	RedirectURI         string          `json:"redirect_uri"`
	CodeChallenge       string          `json:"code_challenge"`
	CodeChallengeMethod string          `json:"code_challenge_method"`
	ProofKey            json.RawMessage `json:"proof_key"`
	RequestHash         string          `json:"request_hash"`
	Name                string          `json:"device_name"`
	State               string          `json:"state"`
}

func (s *Service) authorizeStart(w http.ResponseWriter, r *http.Request) error {
	if err := s.rate(r, "oauth"); err != nil {
		return err
	}
	var input AuthorizationRequest
	if err := decode(w, r, &input, 8192); err != nil {
		return err
	}
	origin, err := Origin(input.ClientID, s.Config.AllowLoopbackHTTP)
	if err != nil {
		return problem(400, "invalid_client_origin")
	}
	// Web grants have exactly one permitted callback and one origin-derived scope.
	if input.RedirectURI != origin+"/?haunt-sync-callback=1" || input.CodeChallengeMethod != "S256" || !identifier.MatchString(input.CodeChallenge) || !identifier.MatchString(input.RequestHash) || !identifier.MatchString(input.State) || len(input.Name) < 1 || len(input.Name) > 128 {
		return problem(400, "invalid_authorization_request")
	}
	if requestOrigin := r.Header.Get("Origin"); requestOrigin != "" && requestOrigin != origin {
		return problem(403, "client_origin_mismatch")
	}
	_, thumb, err := proofKey(input.ProofKey)
	if err != nil {
		return err
	}
	if err = s.verifyProof(r, thumb, ""); err != nil {
		return err
	}
	id := randomID()
	if _, err = s.Pool.Exec(r.Context(), `INSERT INTO authorizations(id,client_id,redirect_uri,code_challenge,request_hash,proof_key,name,state,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,clock_timestamp()+interval '5 minutes')`, id, origin, input.RedirectURI, input.CodeChallenge, input.RequestHash, input.ProofKey, input.Name, input.State); err != nil {
		return err
	}
	write(w, 201, map[string]string{"authorization_id": id, "scope": scope(origin)})
	return nil
}

func (s *Service) authorizeApprove(w http.ResponseWriter, r *http.Request) error {
	device, err := s.authenticate(r)
	if err != nil {
		return err
	}
	if device.Scope != "full" {
		return problem(403, "full_scope_required")
	}
	if origin := r.Header.Get("Origin"); origin != "" && !s.Config.trustedClient(origin) {
		return problem(403, "desktop_approval_required")
	}
	var input struct {
		RequestHash string          `json:"request_hash"`
		Origin      string          `json:"origin"`
		Wrapped     json.RawMessage `json:"wrapped_scope_key"`
	}
	if err = decode(w, r, &input, 8192); err != nil {
		return err
	}
	if len(input.Wrapped) > 4096 || !json.Valid(input.Wrapped) || !identifier.MatchString(input.RequestHash) {
		return problem(400, "invalid_grant")
	}
	id := r.PathValue("id")
	if !identifier.MatchString(id) {
		return problem(400, "invalid_grant")
	}
	code := randomID()
	var redirect, state string
	err = s.Pool.QueryRow(r.Context(), `UPDATE authorizations SET account_id=$2,approved_by=$3,code_hash=$4,wrapped_scope_key=$5 WHERE id=$1 AND account_id IS NULL AND client_id=$6 AND request_hash=$7 AND expires_at>clock_timestamp() RETURNING redirect_uri,state`, id, device.AccountID, device.ID, hash(code), input.Wrapped, input.Origin, input.RequestHash).Scan(&redirect, &state)
	if errors.Is(err, pgx.ErrNoRows) {
		return problem(400, "authorization_expired_or_mismatched")
	}
	if err != nil {
		return err
	}
	callback, err := url.Parse(redirect)
	if err != nil {
		return err
	}
	values := callback.Query()
	values.Set("code", code)
	values.Set("iss", s.Config.Issuer)
	values.Set("state", state)
	callback.RawQuery = values.Encode()
	write(w, 200, map[string]string{"code": code, "redirect_uri": callback.String()})
	return nil
}

func (s *Service) exchangeCode(w http.ResponseWriter, r *http.Request) error {
	var input struct {
		GrantType   string `json:"grant_type"`
		Code        string `json:"code"`
		Verifier    string `json:"code_verifier"`
		ClientID    string `json:"client_id"`
		RedirectURI string `json:"redirect_uri"`
	}
	if err := decode(w, r, &input, 8192); err != nil {
		return err
	}
	if input.GrantType != "authorization_code" || !identifier.MatchString(input.Code) || len(input.Verifier) < 43 || len(input.Verifier) > 128 || strings.ContainsAny(input.Verifier, " \t\r\n") {
		return problem(400, "invalid_grant")
	}
	tx, err := s.Pool.Begin(r.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(r.Context())
	var id, origin, redirect, challenge, name, approvedBy, accountID string
	var public, wrapped json.RawMessage
	err = tx.QueryRow(r.Context(), `SELECT id,client_id,redirect_uri,code_challenge,name,proof_key,wrapped_scope_key,account_id,approved_by FROM authorizations WHERE code_hash=$1 AND consumed_at IS NULL AND expires_at>clock_timestamp() AND account_id IS NOT NULL FOR UPDATE`, hash(input.Code)).Scan(&id, &origin, &redirect, &challenge, &name, &public, &wrapped, &accountID, &approvedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return problem(400, "invalid_grant")
	}
	if err != nil {
		return err
	}
	if input.ClientID != origin || input.RedirectURI != redirect || !hmac.Equal([]byte(challenge), []byte(base64.RawURLEncoding.EncodeToString(hash(input.Verifier)))) {
		return problem(400, "pkce_or_redirect_mismatch")
	}
	if requestOrigin := r.Header.Get("Origin"); requestOrigin != "" && requestOrigin != origin {
		return problem(403, "client_origin_mismatch")
	}
	var active bool
	if err = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM devices WHERE id=$1 AND account_id=$2 AND scope='full' AND revoked_at IS NULL)`, approvedBy, accountID).Scan(&active); err != nil {
		return err
	}
	if !active {
		return problem(400, "authorization_revoked")
	}
	_, thumb, err := proofKey(public)
	if err != nil {
		return err
	}
	if err = s.verifyProof(r, thumb, ""); err != nil {
		return err
	}
	token, deviceID := randomID(), randomID()
	grantScope := scope(origin)
	if _, err = tx.Exec(r.Context(), `INSERT INTO devices(id,account_id,token_hash,proof_key,thumbprint,name,scope,origin) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, deviceID, accountID, hash(token), public, thumb, name, grantScope, origin); err != nil {
		return err
	}
	if _, err = tx.Exec(r.Context(), `UPDATE authorizations SET consumed_at=clock_timestamp() WHERE id=$1`, id); err != nil {
		return err
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	write(w, 200, map[string]any{"access_token": token, "token_type": "DPoP", "account_id": accountID, "device_id": deviceID, "scope": grantScope, "origin": origin, "wrapped_scope_key": wrapped})
	return nil
}
