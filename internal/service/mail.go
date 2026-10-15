package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type Mailer interface {
	Send(context.Context, string, string) error
}
type SMTPMailer struct{ Config Config }

func emailAddress(raw string) (string, error) {
	if len(raw) > 254 || strings.ContainsAny(raw, "\r\n\x00") {
		return "", errors.New("invalid email address")
	}
	parsed, err := mail.ParseAddress(raw)
	if err != nil || parsed.Name != "" || parsed.Address != raw || !strings.Contains(raw, "@") {
		return "", errors.New("invalid email address")
	}
	return strings.ToLower(raw), nil
}

func (m *SMTPMailer) Send(ctx context.Context, recipient, link string) error {
	cfg := m.Config
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(cfg.SMTPHost, cfg.SMTPPort))
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline := time.Now().Add(20 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn.SetDeadline(deadline)
	tlsConfig := &tls.Config{ServerName: cfg.SMTPHost, MinVersion: tls.VersionTLS12}
	if cfg.SMTPCAFile != "" {
		roots, err := x509.SystemCertPool()
		if err != nil {
			return err
		}
		pem, err := os.ReadFile(cfg.SMTPCAFile)
		if err != nil {
			return err
		}
		if !roots.AppendCertsFromPEM(pem) {
			return errors.New("invalid SMTP CA certificate")
		}
		tlsConfig.RootCAs = roots
	}
	if cfg.SMTPPort == "465" {
		secured := tls.Client(conn, tlsConfig)
		if err = secured.HandshakeContext(ctx); err != nil {
			return err
		}
		conn = secured
	}
	client, err := smtp.NewClient(conn, cfg.SMTPHost)
	if err != nil {
		return err
	}
	defer client.Close()
	if cfg.SMTPPort != "465" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return errors.New("SMTP server requires TLS support")
		}
		if err = client.StartTLS(tlsConfig); err != nil {
			return err
		}
	}
	if cfg.SMTPUsername != "" {
		if err = client.Auth(smtp.PlainAuth("", cfg.SMTPUsername, cfg.SMTPPassword, cfg.SMTPHost)); err != nil {
			return err
		}
	}
	if err = client.Mail(cfg.MailFrom); err != nil {
		return err
	}
	if err = client.Rcpt(recipient); err != nil {
		return err
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	body := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: Haunt Sync verification\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nCopy this verification link into the Haunt window that requested it:\r\n%s\r\n\r\nThis link expires in 10 minutes. It verifies email access; it does not unlock your encrypted backup. If you did not request it, ignore this email.\r\n", cfg.MailFrom, recipient, link)
	if _, err = writer.Write([]byte(body)); err != nil {
		return err
	}
	if err = writer.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func (s *Service) emailStart(w http.ResponseWriter, r *http.Request) error {
	if s.Mailer == nil {
		return problem(503, "email_not_configured")
	}
	if err := s.rate(r, "email"); err != nil {
		return err
	}
	var input struct {
		Email    string          `json:"email"`
		Purpose  string          `json:"purpose"`
		ProofKey json.RawMessage `json:"proof_key"`
	}
	if err := decode(w, r, &input, 4096); err != nil {
		return err
	}
	email, err := emailAddress(input.Email)
	if err != nil {
		return problem(400, "invalid_email")
	}
	if input.Purpose != "registration" && input.Purpose != "authentication" && input.Purpose != "recovery" && input.Purpose != "link" {
		return problem(400, "invalid_email_purpose")
	}
	_, thumb, err := proofKey(input.ProofKey)
	if err != nil {
		return err
	}
	if err = s.verifyProof(r, thumb, ""); err != nil {
		return err
	}
	// A separate recipient bucket prevents distributed requests from flooding one mailbox.
	if err = s.rateBucket(r, base64.RawURLEncoding.EncodeToString(hash("email-recipient:"+email)), 3); err != nil {
		return err
	}
	id, token := randomID(), randomID()
	var accountID *string
	if input.Purpose == "authentication" || input.Purpose == "recovery" {
		var found string
		err = s.Pool.QueryRow(r.Context(), `SELECT id FROM accounts WHERE email=$1`, email).Scan(&found)
		if err == nil {
			accountID = &found
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
	}
	if _, err = s.Pool.Exec(r.Context(), `INSERT INTO email_challenges(id,token_hash,account_id,email,purpose,proof_key,thumbprint,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,clock_timestamp()+interval '10 minutes')`, id, hash(token), accountID, email, input.Purpose, input.ProofKey, thumb); err != nil {
		return err
	}
	// Unknown accounts receive the same response but no sign-in message.
	if accountID != nil || input.Purpose == "registration" || input.Purpose == "link" {
		link := s.Config.Issuer + "/#email_id=" + url.QueryEscape(id) + "&email_token=" + url.QueryEscape(token) + "&issuer=" + url.QueryEscape(s.Config.Issuer)
		if err = s.Mailer.Send(r.Context(), email, link); err != nil {
			s.Pool.Exec(r.Context(), `DELETE FROM email_challenges WHERE id=$1`, id)
			return problem(502, "email_delivery_failed")
		}
	}
	write(w, 202, map[string]string{"challenge_id": id})
	return nil
}

func (s *Service) emailVerify(w http.ResponseWriter, r *http.Request) error {
	if err := s.rate(r, "email-verification"); err != nil {
		return err
	}
	var input struct {
		ID    string `json:"challenge_id"`
		Token string `json:"token"`
	}
	if err := decode(w, r, &input, 2048); err != nil {
		return err
	}
	if !identifier.MatchString(input.ID) || !identifier.MatchString(input.Token) {
		return problem(400, "invalid_email_link")
	}
	var thumb string
	err := s.Pool.QueryRow(r.Context(), `SELECT thumbprint FROM email_challenges WHERE id=$1 AND token_hash=$2 AND expires_at>clock_timestamp() AND verified_at IS NULL AND consumed_at IS NULL`, input.ID, hash(input.Token)).Scan(&thumb)
	if errors.Is(err, pgx.ErrNoRows) {
		return problem(400, "email_link_expired_or_used")
	}
	if err != nil {
		return err
	}
	if err = s.verifyProof(r, thumb, ""); err != nil {
		return err
	}
	tag, err := s.Pool.Exec(r.Context(), `UPDATE email_challenges SET verified_at=clock_timestamp() WHERE id=$1 AND verified_at IS NULL AND consumed_at IS NULL AND expires_at>clock_timestamp()`, input.ID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return problem(400, "email_link_expired_or_used")
	}
	write(w, 200, map[string]string{"email_ticket": input.ID})
	return nil
}

func (s *Service) consumeEmailTicket(r *http.Request, tx pgx.Tx, ticket, email, purpose string) error {
	var thumb string
	err := tx.QueryRow(r.Context(), `UPDATE email_challenges SET consumed_at=clock_timestamp() WHERE id=$1 AND email=$2 AND purpose=$3 AND verified_at IS NOT NULL AND consumed_at IS NULL AND expires_at>clock_timestamp() RETURNING thumbprint`, ticket, email, purpose).Scan(&thumb)
	if errors.Is(err, pgx.ErrNoRows) {
		return problem(400, "email_verification_required")
	}
	if err != nil {
		return err
	}
	return s.verifyProof(r, thumb, "")
}

func (s *Service) emailLogin(w http.ResponseWriter, r *http.Request) error {
	var input struct {
		Ticket string `json:"email_ticket"`
		Name   string `json:"device_name"`
	}
	if err := decode(w, r, &input, 2048); err != nil {
		return err
	}
	if !identifier.MatchString(input.Ticket) || len(input.Name) > 128 {
		return problem(400, "invalid_request")
	}
	tx, err := s.Pool.Begin(r.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(r.Context())
	var id, thumb string
	var public json.RawMessage
	err = tx.QueryRow(r.Context(), `UPDATE email_challenges SET consumed_at=clock_timestamp() WHERE id=$1 AND purpose IN ('authentication','recovery') AND account_id IS NOT NULL AND verified_at IS NOT NULL AND consumed_at IS NULL AND expires_at>clock_timestamp() RETURNING account_id,thumbprint,proof_key`, input.Ticket).Scan(&id, &thumb, &public)
	if errors.Is(err, pgx.ErrNoRows) {
		return problem(400, "email_verification_required")
	}
	if err != nil {
		return err
	}
	if err = s.verifyProof(r, thumb, ""); err != nil {
		return err
	}
	token, deviceID := randomID(), randomID()
	if _, err = tx.Exec(r.Context(), `INSERT INTO devices(id,account_id,token_hash,proof_key,thumbprint,name,scope,origin) VALUES($1,$2,$3,$4,$5,$6,'email','')`, deviceID, id, hash(token), public, thumb, input.Name); err != nil {
		return err
	}
	var name string
	var wrapped, recoveryWrapped, recoveryPublic json.RawMessage
	if err = tx.QueryRow(r.Context(), `SELECT username,wrapped_key,coalesce(recovery_wrapped_key,'null'::jsonb),recovery_public_key FROM accounts WHERE id=$1`, id).Scan(&name, &wrapped, &recoveryWrapped, &recoveryPublic); err != nil {
		return err
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	write(w, 200, map[string]any{"access_token": token, "token_type": "DPoP", "device_id": deviceID, "account_id": id, "username": name, "scope": "email", "wrapped_key": wrapped, "recovery_wrapped_key": recoveryWrapped, "recovery_public_key": recoveryPublic})
	return nil
}

func (s *Service) emailLink(w http.ResponseWriter, r *http.Request) error {
	device, err := s.authenticate(r)
	if err != nil {
		return err
	}
	if device.Scope != "full" {
		return problem(403, "full_scope_required")
	}
	var input struct {
		Email  string `json:"email"`
		Ticket string `json:"email_ticket"`
	}
	if err = decode(w, r, &input, 2048); err != nil {
		return err
	}
	email, err := emailAddress(input.Email)
	if err != nil {
		return problem(400, "invalid_email")
	}
	tx, err := s.Pool.Begin(r.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(r.Context())
	if _, err = tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, email); err != nil {
		return err
	}
	var thumb string
	err = tx.QueryRow(r.Context(), `UPDATE email_challenges SET consumed_at=clock_timestamp() WHERE id=$1 AND email=$2 AND purpose='link' AND verified_at IS NOT NULL AND consumed_at IS NULL AND expires_at>clock_timestamp() RETURNING thumbprint`, input.Ticket, email).Scan(&thumb)
	if errors.Is(err, pgx.ErrNoRows) {
		return problem(400, "email_verification_required")
	}
	if err != nil {
		return err
	}
	if thumb != device.Thumbprint {
		return problem(403, "proof_key_mismatch")
	}
	tag, err := tx.Exec(r.Context(), `UPDATE accounts SET email=$1 WHERE id=$2 AND NOT EXISTS(SELECT 1 FROM accounts WHERE (email=$1 OR username=$1) AND id<>$2)`, email, device.AccountID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return problem(409, "email_already_used")
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	w.WriteHeader(204)
	return nil
}
