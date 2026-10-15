package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/bytemare/opaque"
	"github.com/example-git/haunt-sync/internal/protocol"
	"github.com/jackc/pgx/v5"
	"net/http"
	"regexp"
	"strings"
)

var accountName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,63}$`)

func username(raw string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if accountName.MatchString(value) {
		return value, nil
	}
	if email, err := emailAddress(value); err == nil {
		return email, nil
	}
	return "", problem(400, "invalid_account_name")
}
func message(raw string) ([]byte, error) {
	if len(raw) > 4096 {
		return nil, problem(400, "invalid_auth_message")
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, problem(400, "invalid_auth_message")
	}
	return b, nil
}

type Ciphertext struct {
	Version int    `json:"version"`
	Nonce   string `json:"nonce"`
	Data    string `json:"data"`
}

func (c Ciphertext) validate(maximum int) error {
	nonce, err := base64.RawURLEncoding.DecodeString(c.Nonce)
	if c.Version != 1 || err != nil || len(nonce) != 12 || len(c.Data) > maximum {
		return problem(400, "invalid_ciphertext")
	}
	data, err := base64.RawURLEncoding.DecodeString(c.Data)
	if err != nil || len(data) < 16 {
		return problem(400, "invalid_ciphertext")
	}
	return nil
}

type account struct {
	ID, Username                             string
	CredentialID, Record                     []byte
	Wrapped, RecoveryPublic, RecoveryWrapped json.RawMessage
}

func (s *Service) lookup(r *http.Request, name string) (account, error) {
	var a account
	err := s.Pool.QueryRow(r.Context(), `SELECT id,username,credential_id,record,wrapped_key,recovery_public_key,coalesce(recovery_wrapped_key,'null'::jsonb) FROM accounts WHERE username=$1 OR email=$1`, name).Scan(&a.ID, &a.Username, &a.CredentialID, &a.Record, &a.Wrapped, &a.RecoveryPublic, &a.RecoveryWrapped)
	return a, err
}

func (s *Service) registrationStart(w http.ResponseWriter, r *http.Request) error {
	if err := s.rate(r, "registration"); err != nil {
		return err
	}
	var input struct {
		Username string `json:"username"`
		Request  string `json:"request"`
	}
	if err := decode(w, r, &input, 8192); err != nil {
		return err
	}
	name, err := username(input.Username)
	if err != nil {
		return err
	}
	if _, err = s.lookup(r, name); err == nil {
		return problem(409, "account_exists")
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	wire, err := message(input.Request)
	if err != nil {
		return err
	}
	request, err := s.Opaque.Deserialize.RegistrationRequest(wire)
	if err != nil {
		return problem(400, "invalid_auth_message")
	}
	id, accountID, credentialID := randomID(), randomID(), []byte(randomID())
	reply, err := s.Opaque.RegistrationResponse(request, credentialID, nil)
	if err != nil {
		return problem(400, "invalid_auth_message")
	}
	if _, err = s.Pool.Exec(r.Context(), `INSERT INTO challenges(id,kind,username,account_id,credential_id,expires_at) VALUES($1,'registration',$2,$3,$4,clock_timestamp()+interval '2 minutes')`, id, name, accountID, credentialID); err != nil {
		return err
	}
	write(w, 200, map[string]any{"challenge_id": id, "account_id": accountID, "username": name, "response": base64.RawURLEncoding.EncodeToString(reply.Serialize())})
	return nil
}

func (s *Service) registrationFinish(w http.ResponseWriter, r *http.Request) error {
	var input struct {
		Challenge       string          `json:"challenge_id"`
		Record          string          `json:"record"`
		Wrapped         Ciphertext      `json:"wrapped_key"`
		RecoveryPublic  json.RawMessage `json:"recovery_public_key"`
		RecoveryWrapped *Ciphertext     `json:"recovery_wrapped_key,omitempty"`
		EmailTicket     string          `json:"email_ticket,omitempty"`
	}
	if err := decode(w, r, &input, 16384); err != nil {
		return err
	}
	if !identifier.MatchString(input.Challenge) {
		return problem(400, "invalid_challenge")
	}
	if err := input.Wrapped.validate(4096); err != nil {
		return err
	}
	if _, _, err := proofKey(input.RecoveryPublic); err != nil {
		return err
	}
	if input.RecoveryWrapped != nil {
		if err := input.RecoveryWrapped.validate(4096); err != nil {
			return err
		}
	}
	wire, err := message(input.Record)
	if err != nil {
		return err
	}
	if _, err = s.Opaque.Deserialize.RegistrationRecord(wire); err != nil {
		return problem(400, "invalid_auth_message")
	}
	tx, err := s.Pool.Begin(r.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(r.Context())
	var name, id string
	var credentialID []byte
	err = tx.QueryRow(r.Context(), `DELETE FROM challenges WHERE id=$1 AND kind='registration' AND expires_at>clock_timestamp() RETURNING username,account_id,credential_id`, input.Challenge).Scan(&name, &id, &credentialID)
	if errors.Is(err, pgx.ErrNoRows) {
		return problem(400, "challenge_expired_or_used")
	}
	if err != nil {
		return err
	}
	var email *string
	if strings.Contains(name, "@") {
		if _, err = tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, name); err != nil {
			return err
		}
		var claimed bool
		if err = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM accounts WHERE username=$1 OR email=$1)`, name).Scan(&claimed); err != nil {
			return err
		}
		if claimed {
			return problem(409, "account_exists")
		}
		if err = s.consumeEmailTicket(r, tx, input.EmailTicket, name, "registration"); err != nil {
			return err
		}
		email = &name
	}
	wrapped, _ := json.Marshal(input.Wrapped)
	recoveryWrapped, _ := json.Marshal(input.RecoveryWrapped)
	tag, err := tx.Exec(r.Context(), `INSERT INTO accounts(id,username,credential_id,record,wrapped_key,recovery_public_key,recovery_wrapped_key,email) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`, id, name, credentialID, wire, wrapped, input.RecoveryPublic, recoveryWrapped, email)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return problem(409, "account_exists")
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	write(w, 201, map[string]string{"account_id": id, "username": name})
	return nil
}

func (s *Service) loginStart(w http.ResponseWriter, r *http.Request) error {
	if err := s.rate(r, "login"); err != nil {
		return err
	}
	var input struct {
		Username string          `json:"username"`
		Request  string          `json:"request"`
		ProofKey json.RawMessage `json:"proof_key"`
	}
	if err := decode(w, r, &input, 8192); err != nil {
		return err
	}
	name, err := username(input.Username)
	if err != nil {
		return err
	}
	if _, _, err = proofKey(input.ProofKey); err != nil {
		return err
	}
	wire, err := message(input.Request)
	if err != nil {
		return err
	}
	ke1, err := s.Opaque.Deserialize.KE1(wire)
	if err != nil {
		return problem(400, "invalid_auth_message")
	}
	a, err := s.lookup(r, name)
	known := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	var record *opaque.ClientRecord
	if known {
		parsed, e := s.Opaque.Deserialize.RegistrationRecord(a.Record)
		if e != nil {
			return e
		}
		record = &opaque.ClientRecord{CredentialIdentifier: a.CredentialID, ClientIdentity: []byte(a.ID), RegistrationRecord: parsed}
	} else {
		mac := hmac.New(sha256.New, s.Opaque.ServerKeyMaterial.OPRFGlobalSeed)
		mac.Write([]byte(name))
		a.ID = base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		record, err = protocol.Configuration().GetFakeRecord([]byte(a.ID))
		if err != nil {
			return err
		}
		record.ClientIdentity = []byte(a.ID)
	}
	reply, output, err := s.Opaque.GenerateKE2(ke1, record)
	if err != nil {
		return problem(400, "invalid_auth_message")
	}
	defer clear(output.SessionSecret)
	defer clear(output.ClientMAC)
	id := randomID()
	var accountID *string
	if known {
		accountID = &a.ID
	}
	if _, err = s.Pool.Exec(r.Context(), `INSERT INTO challenges(id,kind,username,account_id,expected_mac,session_secret,proof_key,expires_at) VALUES($1,'login',$2,$3,$4,$5,$6,clock_timestamp()+interval '2 minutes')`, id, name, accountID, output.ClientMAC, output.SessionSecret, input.ProofKey); err != nil {
		return err
	}
	write(w, 200, map[string]any{"challenge_id": id, "account_id": a.ID, "response": base64.RawURLEncoding.EncodeToString(reply.Serialize())})
	return nil
}

func (s *Service) loginFinish(w http.ResponseWriter, r *http.Request) error {
	var input struct {
		Challenge string `json:"challenge_id"`
		Message   string `json:"message"`
		Binding   string `json:"binding"`
		Name      string `json:"device_name"`
	}
	if err := decode(w, r, &input, 8192); err != nil {
		return err
	}
	if !identifier.MatchString(input.Challenge) || len(input.Name) < 1 || len(input.Name) > 128 {
		return problem(400, "invalid_request")
	}
	wire, err := message(input.Message)
	if err != nil {
		return err
	}
	ke3, err := s.Opaque.Deserialize.KE3(wire)
	if err != nil {
		return problem(401, "authentication_failed")
	}
	tx, err := s.Pool.Begin(r.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(r.Context())
	var accountID *string
	// Use the same account-first lock order as secret rotation and uploads.
	if err = tx.QueryRow(r.Context(), `SELECT account_id FROM challenges WHERE id=$1 AND kind='login'`, input.Challenge).Scan(&accountID); errors.Is(err, pgx.ErrNoRows) {
		return problem(401, "challenge_expired_or_used")
	} else if err != nil {
		return err
	}
	if accountID != nil {
		var locked string
		if err = tx.QueryRow(r.Context(), `SELECT id FROM accounts WHERE id=$1 FOR SHARE`, *accountID).Scan(&locked); err != nil {
			return err
		}
	}
	var expected, sessionKey []byte
	var public json.RawMessage
	err = tx.QueryRow(r.Context(), `DELETE FROM challenges WHERE id=$1 AND kind='login' AND expires_at>clock_timestamp() RETURNING account_id,expected_mac,session_secret,proof_key`, input.Challenge).Scan(&accountID, &expected, &sessionKey, &public)
	if errors.Is(err, pgx.ErrNoRows) {
		return problem(401, "challenge_expired_or_used")
	}
	if err != nil {
		return err
	}
	defer clear(expected)
	defer clear(sessionKey)
	if s.Opaque.LoginFinish(ke3, expected) != nil || accountID == nil {
		tx.Commit(r.Context())
		return problem(401, "authentication_failed")
	}
	_, thumb, err := proofKey(public)
	if err != nil {
		return err
	}
	binding := protocol.LoginBinding(sessionKey, s.Config.Issuer, input.Challenge, thumb)
	if !hmac.Equal([]byte(binding), []byte(input.Binding)) {
		tx.Commit(r.Context())
		return problem(401, "device_binding_failed")
	}
	if err = s.verifyProof(r, thumb, ""); err != nil {
		return err
	}
	token, id := randomID(), randomID()
	if _, err = tx.Exec(r.Context(), `INSERT INTO devices(id,account_id,token_hash,proof_key,thumbprint,name,scope,origin) VALUES($1,$2,$3,$4,$5,$6,'full','')`, id, *accountID, hash(token), public, thumb, input.Name); err != nil {
		return err
	}
	var wrapped, recoveryPublic, recoveryWrapped json.RawMessage
	var name string
	if err = tx.QueryRow(r.Context(), `SELECT username,wrapped_key,recovery_public_key,coalesce(recovery_wrapped_key,'null'::jsonb) FROM accounts WHERE id=$1`, *accountID).Scan(&name, &wrapped, &recoveryPublic, &recoveryWrapped); err != nil {
		return err
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	write(w, 200, map[string]any{"account_id": *accountID, "username": name, "access_token": token, "token_type": "DPoP", "device_id": id, "scope": "full", "wrapped_key": wrapped, "recovery_public_key": recoveryPublic, "recovery_wrapped_key": recoveryWrapped})
	return nil
}
