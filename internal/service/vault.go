package service

import (
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"net/http"
	"strconv"
	"strings"
)

func (s *Service) vaultOrigins(w http.ResponseWriter, r *http.Request) error {
	device, err := s.authenticate(r)
	if err != nil {
		return err
	}
	if device.Scope != "full" {
		return problem(403, "full_scope_required")
	}
	rows, err := s.Pool.Query(r.Context(), `SELECT DISTINCT origin FROM devices WHERE account_id=$1 AND origin<>'' AND scope LIKE 'server:%' ORDER BY origin`, device.AccountID)
	if err != nil {
		return err
	}
	defer rows.Close()
	origins := []string{}
	for rows.Next() {
		var value string
		if err = rows.Scan(&value); err != nil {
			return err
		}
		origins = append(origins, value)
	}
	if err = rows.Err(); err != nil {
		return err
	}
	write(w, 200, map[string]any{"origins": origins})
	return nil
}

func vaultScope(device Device, name string) error {
	if strings.HasPrefix(name, "archive-chunk:") {
		name = strings.TrimPrefix(name, "archive-chunk:")
		index := strings.LastIndexByte(name, ':')
		if index < 0 || !identifier.MatchString(name[index+1:]) {
			return problem(400, "invalid_vault_scope")
		}
		name = name[:index]
	} else {
		name = strings.TrimPrefix(name, "archive:")
	}
	if name != "full" && (len(name) != 50 || name[:7] != "server:" || !identifier.MatchString(name[7:])) {
		return problem(400, "invalid_vault_scope")
	}
	if device.Scope != "full" && device.Scope != name {
		return problem(403, "vault_scope_denied")
	}
	return nil
}

func (s *Service) vaultGet(w http.ResponseWriter, r *http.Request) error {
	device, err := s.authenticate(r)
	if err != nil {
		return err
	}
	name := r.PathValue("scope")
	if err = vaultScope(device, name); err != nil {
		return err
	}
	var revision, sequence int64
	var ciphertext json.RawMessage
	var known int64
	if raw := r.URL.Query().Get("known_revision"); raw != "" {
		known, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || known < 0 || known > 1<<52 {
			return problem(400, "invalid_revision")
		}
	}
	err = s.Pool.QueryRow(r.Context(), `SELECT revision,change_sequence,CASE WHEN revision=$3 THEN NULL ELSE ciphertext END FROM vaults WHERE account_id=$1 AND scope=$2`, device.AccountID, name, known).Scan(&revision, &sequence, &ciphertext)
	if errors.Is(err, pgx.ErrNoRows) {
		write(w, 200, map[string]any{"revision": 0, "ciphertext": nil})
		return nil
	}
	if err != nil {
		return err
	}
	if revision == known {
		write(w, 200, map[string]any{"revision": revision, "ciphertext": nil, "unchanged": true})
		return nil
	}
	write(w, 200, map[string]any{"revision": revision, "sequence": sequence, "ciphertext": ciphertext})
	return nil
}

func (s *Service) vaultPut(w http.ResponseWriter, r *http.Request) error {
	device, err := s.authenticate(r)
	if err != nil {
		return err
	}
	name := r.PathValue("scope")
	if err = vaultScope(device, name); err != nil {
		return err
	}
	var input struct {
		Expected   int64      `json:"expected_revision"`
		Ciphertext Ciphertext `json:"ciphertext"`
	}
	if err = decode(w, r, &input, 32<<20); err != nil {
		return err
	}
	if input.Expected < 0 || input.Expected > 1<<52 {
		return problem(400, "invalid_revision")
	}
	if err = input.Ciphertext.validate(30 << 20); err != nil {
		return err
	}
	tx, err := s.Pool.Begin(r.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(r.Context())
	var sequence int64
	if err = tx.QueryRow(r.Context(), `UPDATE accounts SET vault_sequence=vault_sequence+1 WHERE id=$1 RETURNING vault_sequence`, device.AccountID).Scan(&sequence); err != nil {
		return err
	}
	var active bool
	if err = tx.QueryRow(r.Context(), `SELECT revoked_at IS NULL FROM devices WHERE id=$1 AND account_id=$2`, device.ID, device.AccountID).Scan(&active); err != nil {
		return err
	}
	if !active {
		return problem(401, "authentication_failed")
	}
	encoded, _ := json.Marshal(input.Ciphertext)
	var revision int64
	if input.Expected == 0 {
		err = tx.QueryRow(r.Context(), `INSERT INTO vaults(account_id,scope,revision,ciphertext,change_sequence) VALUES($1,$2,1,$3,$4) ON CONFLICT DO NOTHING RETURNING revision`, device.AccountID, name, encoded, sequence).Scan(&revision)
	} else {
		err = tx.QueryRow(r.Context(), `UPDATE vaults SET revision=revision+1,ciphertext=$3,updated_at=clock_timestamp(),change_sequence=$5 WHERE account_id=$1 AND scope=$2 AND revision=$4 RETURNING revision`, device.AccountID, name, encoded, input.Expected, sequence).Scan(&revision)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return problem(409, "revision_conflict")
	}
	if err != nil {
		return err
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	write(w, 200, map[string]int64{"revision": revision, "sequence": sequence})
	return nil
}
