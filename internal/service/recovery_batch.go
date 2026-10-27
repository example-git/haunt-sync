package service

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"
)

func (s *Service) recoveryBatch(r *http.Request) (tx pgx.Tx, device Device, cursor, digest string, err error) {
	device, err = s.authenticate(r)
	if err != nil {
		return
	}
	if device.Scope != "full" && device.Scope != "email" {
		err = problem(403, "recovery_scope_required")
		return
	}
	id := r.PathValue("challenge")
	if !identifier.MatchString(id) {
		err = problem(400, "invalid_recovery")
		return
	}
	tx, err = s.Pool.Begin(r.Context())
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			tx.Rollback(r.Context())
		}
	}()
	var account string
	if err = tx.QueryRow(r.Context(), `SELECT id FROM accounts WHERE id=$1 FOR SHARE`, device.AccountID).Scan(&account); err != nil {
		return
	}
	var active bool
	if err = tx.QueryRow(r.Context(), `SELECT revoked_at IS NULL FROM devices WHERE id=$1`, device.ID).Scan(&active); err != nil {
		return
	}
	if !active {
		err = problem(401, "authentication_failed")
		return
	}
	var public json.RawMessage
	err = tx.QueryRow(r.Context(), `SELECT c.proof_key,b.cursor,b.digest FROM challenges c JOIN recovery_batches b ON b.challenge_id=c.id WHERE c.id=$1 AND c.account_id=$2 AND c.kind='recovery' AND c.expires_at>clock_timestamp() FOR UPDATE OF c,b`, id, device.AccountID).Scan(&public, &cursor, &digest)
	if errors.Is(err, pgx.ErrNoRows) {
		err = problem(400, "challenge_expired_or_used")
		return
	}
	if err != nil {
		return
	}
	var thumb string
	_, thumb, err = proofKey(public)
	if err != nil {
		return
	}
	if thumb != device.Thumbprint {
		err = problem(403, "proof_key_mismatch")
		return
	}
	_, err = tx.Exec(r.Context(), `UPDATE challenges SET expires_at=clock_timestamp()+interval '15 minutes' WHERE id=$1`, id)
	return
}

func (s *Service) recoveryNext(w http.ResponseWriter, r *http.Request) error {
	tx, device, cursor, digest, err := s.recoveryBatch(r)
	if err != nil {
		return err
	}
	defer tx.Rollback(r.Context())
	var scope string
	var expected int64
	var revision *int64
	var ciphertext json.RawMessage
	err = tx.QueryRow(r.Context(), `SELECT m.scope,m.expected_revision,v.revision,v.ciphertext FROM recovery_vaults m LEFT JOIN vaults v ON v.account_id=$2 AND v.scope=m.scope WHERE m.challenge_id=$1 AND m.scope>$3 ORDER BY m.scope LIMIT 1`, r.PathValue("challenge"), device.AccountID, cursor).Scan(&scope, &expected, &revision, &ciphertext)
	var vault any
	if !errors.Is(err, pgx.ErrNoRows) {
		if err != nil {
			return err
		}
		if revision == nil || *revision != expected {
			return problem(409, "migration_conflict")
		}
		vault = map[string]any{"scope": scope, "revision": expected, "ciphertext": ciphertext}
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	write(w, 200, map[string]any{"vault": vault, "digest": digest})
	return nil
}

func (s *Service) recoveryStage(w http.ResponseWriter, r *http.Request) error {
	var input struct {
		Expected   int64      `json:"expected_revision"`
		Ciphertext Ciphertext `json:"ciphertext"`
		Previous   string     `json:"previous_hash"`
	}
	if err := decode(w, r, &input, 32<<20); err != nil {
		return err
	}
	if input.Expected < 1 || input.Expected > 1<<52 || !identifier.MatchString(input.Previous) {
		return problem(400, "invalid_migration")
	}
	if err := input.Ciphertext.validate(30 << 20); err != nil {
		return err
	}
	tx, device, cursor, digest, err := s.recoveryBatch(r)
	if err != nil {
		return err
	}
	defer tx.Rollback(r.Context())
	scope := r.PathValue("scope")
	if err = vaultScope(Device{Scope: "full"}, scope); err != nil {
		return err
	}
	nextHash := base64.RawURLEncoding.EncodeToString(hash(input.Previous + "\x00" + scope + "\x00" + strconv.FormatInt(input.Expected, 10) + "\x001\x00" + input.Ciphertext.Nonce + "\x00" + input.Ciphertext.Data))
	if scope != cursor || nextHash != digest {
		if input.Previous != digest {
			return problem(409, "migration_conflict")
		}
		var next string
		err = tx.QueryRow(r.Context(), `SELECT scope FROM recovery_vaults WHERE challenge_id=$1 AND scope>$2 ORDER BY scope LIMIT 1`, r.PathValue("challenge"), cursor).Scan(&next)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && next != scope) {
			return problem(409, "migration_conflict")
		}
		if err != nil {
			return err
		}
		ciphertext, _ := json.Marshal(input.Ciphertext)
		tag, err := tx.Exec(r.Context(), `UPDATE recovery_vaults m SET ciphertext=$4 FROM vaults v WHERE m.challenge_id=$1 AND m.scope=$2 AND m.expected_revision=$3 AND v.account_id=$5 AND v.scope=m.scope AND v.revision=m.expected_revision`, r.PathValue("challenge"), scope, input.Expected, ciphertext, device.AccountID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return problem(409, "migration_conflict")
		}
		if _, err = tx.Exec(r.Context(), `UPDATE recovery_batches SET cursor=$2,digest=$3 WHERE challenge_id=$1`, r.PathValue("challenge"), scope, nextHash); err != nil {
			return err
		}
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	write(w, 200, map[string]string{"digest": nextHash})
	return nil
}
