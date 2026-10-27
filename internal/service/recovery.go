package service

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"
)

func (s *Service) recoveryStart(w http.ResponseWriter, r *http.Request) error {
	device, err := s.authenticate(r)
	if err != nil {
		return err
	}
	if device.Scope != "full" && device.Scope != "email" {
		return problem(403, "recovery_scope_required")
	}
	var input struct {
		Request string `json:"request"`
		Paged   bool   `json:"paged_vaults"`
	}
	if err = decode(w, r, &input, 8192); err != nil {
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
	var credentialID []byte
	var name string
	var public json.RawMessage
	if err = s.Pool.QueryRow(r.Context(), `SELECT a.credential_id,a.username,d.proof_key FROM accounts a JOIN devices d ON d.account_id=a.id WHERE a.id=$1 AND d.id=$2 AND d.revoked_at IS NULL`, device.AccountID, device.ID).Scan(&credentialID, &name, &public); err != nil {
		return err
	}
	reply, err := s.Opaque.RegistrationResponse(request, credentialID, nil)
	if err != nil {
		return problem(400, "invalid_auth_message")
	}
	id := randomID()
	if input.Paged {
		tx, err := s.Pool.Begin(r.Context())
		if err != nil {
			return err
		}
		defer tx.Rollback(r.Context())
		var account string
		if err = tx.QueryRow(r.Context(), `SELECT id FROM accounts WHERE id=$1 FOR SHARE`, device.AccountID).Scan(&account); err != nil {
			return err
		}
		var active bool
		if err = tx.QueryRow(r.Context(), `SELECT revoked_at IS NULL FROM devices WHERE id=$1`, device.ID).Scan(&active); err != nil {
			return err
		}
		if !active {
			return problem(401, "authentication_failed")
		}
		if _, err = tx.Exec(r.Context(), `INSERT INTO challenges(id,kind,username,account_id,credential_id,proof_key,expires_at) VALUES($1,'recovery',$2,$3,$4,$5,clock_timestamp()+interval '15 minutes')`, id, name, device.AccountID, credentialID, public); err != nil {
			return err
		}
		if _, err = tx.Exec(r.Context(), `INSERT INTO recovery_batches(challenge_id,digest) VALUES($1,$2)`, id, base64.RawURLEncoding.EncodeToString(hash("haunt-sync-migration-v1"))); err != nil {
			return err
		}
		if _, err = tx.Exec(r.Context(), `INSERT INTO recovery_vaults(challenge_id,scope,expected_revision) SELECT $1,scope,revision FROM vaults WHERE account_id=$2`, id, device.AccountID); err != nil {
			return err
		}
		if err = tx.Commit(r.Context()); err != nil {
			return err
		}
		write(w, 200, map[string]any{"challenge_id": id, "account_id": device.AccountID, "username": name, "response": base64.RawURLEncoding.EncodeToString(reply.Serialize()), "paged_vaults": true})
		return nil
	}
	if _, err = s.Pool.Exec(r.Context(), `INSERT INTO challenges(id,kind,username,account_id,credential_id,proof_key,expires_at) VALUES($1,'recovery',$2,$3,$4,$5,clock_timestamp()+interval '2 minutes')`, id, name, device.AccountID, credentialID, public); err != nil {
		return err
	}
	rows, err := s.Pool.Query(r.Context(), `SELECT scope,revision,ciphertext FROM vaults WHERE account_id=$1 ORDER BY scope`, device.AccountID)
	if err != nil {
		return err
	}
	defer rows.Close()
	vaults := []map[string]any{}
	for rows.Next() {
		var scope string
		var revision int64
		var ciphertext json.RawMessage
		if err = rows.Scan(&scope, &revision, &ciphertext); err != nil {
			return err
		}
		vaults = append(vaults, map[string]any{"scope": scope, "revision": revision, "ciphertext": ciphertext})
	}
	if err = rows.Err(); err != nil {
		return err
	}
	write(w, 200, map[string]any{"challenge_id": id, "account_id": device.AccountID, "username": name, "response": base64.RawURLEncoding.EncodeToString(reply.Serialize()), "vaults": vaults})
	return nil
}

type recoveryClaims struct {
	Issuer              string `json:"issuer"`
	Account             string `json:"account_id"`
	Challenge           string `json:"challenge_id"`
	Thumb               string `json:"device_thumbprint"`
	RecordHash          string `json:"record_hash"`
	WrappedHash         string `json:"wrapped_key_hash"`
	VaultsHash          string `json:"vaults_hash"`
	RecoveryWrappedHash string `json:"recovery_wrapped_key_hash"`
	RecoveryPublicHash  string `json:"recovery_public_key_hash"`
}

func (s *Service) recoveryFinish(w http.ResponseWriter, r *http.Request) error {
	device, err := s.authenticate(r)
	if err != nil {
		return err
	}
	if device.Scope != "full" && device.Scope != "email" {
		return problem(403, "recovery_scope_required")
	}
	var input struct {
		Challenge       string          `json:"challenge_id"`
		Staged          bool            `json:"staged_vaults"`
		Record          string          `json:"record"`
		Wrapped         Ciphertext      `json:"wrapped_key"`
		Proof           string          `json:"recovery_proof"`
		RecoveryWrapped *Ciphertext     `json:"recovery_wrapped_key"`
		RecoveryPublic  json.RawMessage `json:"recovery_public_key"`
		Vaults          *[]struct {
			Scope      string     `json:"scope"`
			Expected   int64      `json:"expected_revision"`
			Ciphertext Ciphertext `json:"ciphertext"`
		} `json:"vaults"`
	}
	if err = decode(w, r, &input, 128<<20); err != nil {
		return err
	}
	if !identifier.MatchString(input.Challenge) || len(input.Proof) > 8192 {
		return problem(400, "invalid_recovery")
	}
	if err = input.Wrapped.validate(4096); err != nil {
		return err
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
	var account string
	if err = tx.QueryRow(r.Context(), `SELECT id FROM accounts WHERE id=$1 FOR UPDATE`, device.AccountID).Scan(&account); err != nil {
		return err
	}
	var public json.RawMessage
	err = tx.QueryRow(r.Context(), `SELECT proof_key FROM challenges WHERE id=$1 AND kind='recovery' AND account_id=$2 AND expires_at>clock_timestamp() FOR UPDATE`, input.Challenge, device.AccountID).Scan(&public)
	if errors.Is(err, pgx.ErrNoRows) {
		return problem(400, "challenge_expired_or_used")
	}
	if err != nil {
		return err
	}
	_, thumb, err := proofKey(public)
	if err != nil {
		return err
	}
	if thumb != device.Thumbprint {
		return problem(403, "proof_key_mismatch")
	}
	var recoveryPublic json.RawMessage
	if err = tx.QueryRow(r.Context(), `SELECT recovery_public_key FROM accounts WHERE id=$1 FOR UPDATE`, device.AccountID).Scan(&recoveryPublic); err != nil {
		return err
	}
	key, _, err := proofKey(recoveryPublic)
	if err != nil {
		return err
	}
	signed, err := jose.ParseSignedCompact(input.Proof, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil || len(signed.Signatures) != 1 || signed.Signatures[0].Protected.ExtraHeaders[jose.HeaderType] != "haunt-sync-recovery+jwt" {
		return problem(403, "recovery_key_required")
	}
	payload, err := signed.Verify(key.Key)
	if err != nil {
		return problem(403, "recovery_key_required")
	}
	var claims recoveryClaims
	// Hash the specified fields rather than JSON bytes, whose formatting can change in transit.
	wrappedHash := base64.RawURLEncoding.EncodeToString(hash("1\x00" + input.Wrapped.Nonce + "\x00" + input.Wrapped.Data))
	if json.Unmarshal(payload, &claims) != nil || claims.Issuer != s.Config.Issuer || claims.Account != device.AccountID || claims.Challenge != input.Challenge || claims.Thumb != device.Thumbprint || claims.RecordHash != base64.RawURLEncoding.EncodeToString(hash(input.Record)) || claims.WrappedHash != wrappedHash {
		return problem(403, "invalid_recovery_proof")
	}
	// Lock only this account. Concurrent uploads must finish before rotation,
	// and every revision in the client's complete migration must still match.
	var active bool
	if err = tx.QueryRow(r.Context(), `SELECT revoked_at IS NULL FROM devices WHERE id=$1 AND account_id=$2`, device.ID, device.AccountID).Scan(&active); err != nil {
		return err
	}
	if !active {
		return problem(401, "authentication_failed")
	}
	if input.Vaults != nil || input.Staged {
		if input.RecoveryWrapped == nil || (input.Staged && input.Vaults != nil) || (input.Vaults != nil && len(*input.Vaults) > 256) {
			return problem(400, "invalid_migration")
		}
		if err = input.RecoveryWrapped.validate(4096); err != nil {
			return err
		}
		values := []any{}
		seen := map[string]bool{}
		if input.Vaults != nil {
			for _, vault := range *input.Vaults {
				if seen[vault.Scope] || vault.Expected < 1 || vault.Expected > 1<<52 {
					return problem(400, "invalid_migration")
				}
				if err = vaultScope(Device{Scope: "full"}, vault.Scope); err != nil {
					return err
				}
				if err = vault.Ciphertext.validate(30 << 20); err != nil {
					return err
				}
				seen[vault.Scope] = true
				values = append(values, []any{vault.Scope, vault.Expected, vault.Ciphertext.Version, vault.Ciphertext.Nonce, vault.Ciphertext.Data})
			}
		}
		encoded, _ := json.Marshal(values)
		migrationHash := base64.RawURLEncoding.EncodeToString(hash(string(encoded)))
		if input.Staged {
			if err = tx.QueryRow(r.Context(), `SELECT digest FROM recovery_batches WHERE challenge_id=$1`, input.Challenge).Scan(&migrationHash); errors.Is(err, pgx.ErrNoRows) {
				return problem(400, "invalid_migration")
			} else if err != nil {
				return err
			}
		}
		recoveryHash := base64.RawURLEncoding.EncodeToString(hash("1\x00" + input.RecoveryWrapped.Nonce + "\x00" + input.RecoveryWrapped.Data))
		if _, _, err = proofKey(input.RecoveryPublic); err != nil {
			return err
		}
		var publicFields struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}
		if err = json.Unmarshal(input.RecoveryPublic, &publicFields); err != nil {
			return problem(400, "invalid_recovery_public_key")
		}
		publicEncoded, _ := json.Marshal([]string{publicFields.Kty, publicFields.Crv, publicFields.X, publicFields.Y})
		if claims.RecoveryPublicHash != base64.RawURLEncoding.EncodeToString(hash(string(publicEncoded))) {
			return problem(403, "invalid_recovery_public_key_proof")
		}
		if claims.VaultsHash != migrationHash || claims.RecoveryWrappedHash != recoveryHash {
			return problem(403, "invalid_migration_proof")
		}
		var count int
		if err = tx.QueryRow(r.Context(), `SELECT count(*) FROM vaults WHERE account_id=$1`, device.AccountID).Scan(&count); err != nil {
			return err
		}
		if input.Staged {
			var staged int
			var mismatch bool
			if err = tx.QueryRow(r.Context(), `SELECT count(*) FROM recovery_vaults WHERE challenge_id=$1 AND ciphertext IS NOT NULL`, input.Challenge).Scan(&staged); err != nil {
				return err
			}
			if err = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM vaults v LEFT JOIN recovery_vaults m ON m.challenge_id=$2 AND m.scope=v.scope WHERE v.account_id=$1 AND (m.scope IS NULL OR m.ciphertext IS NULL OR m.expected_revision<>v.revision))`, device.AccountID, input.Challenge).Scan(&mismatch); err != nil {
				return err
			}
			if staged != count || mismatch {
				return problem(409, "migration_conflict")
			}
			if _, err = tx.Exec(r.Context(), `UPDATE vaults v SET revision=v.revision+1,ciphertext=m.ciphertext,updated_at=clock_timestamp() FROM recovery_vaults m WHERE m.challenge_id=$2 AND v.account_id=$1 AND v.scope=m.scope`, device.AccountID, input.Challenge); err != nil {
				return err
			}
		} else {
			if count != len(*input.Vaults) {
				return problem(409, "migration_conflict")
			}
			for _, vault := range *input.Vaults {
				ciphertext, _ := json.Marshal(vault.Ciphertext)
				tag, e := tx.Exec(r.Context(), `UPDATE vaults SET revision=revision+1,ciphertext=$3,updated_at=clock_timestamp() WHERE account_id=$1 AND scope=$2 AND revision=$4`, device.AccountID, vault.Scope, ciphertext, vault.Expected)
				if e != nil {
					return e
				}
				if tag.RowsAffected() != 1 {
					return problem(409, "migration_conflict")
				}
			}
		}
		var sequence int64
		if err = tx.QueryRow(r.Context(), `SELECT vault_sequence FROM accounts WHERE id=$1`, device.AccountID).Scan(&sequence); err != nil {
			return err
		}
		if _, err = tx.Exec(r.Context(), `WITH numbered AS (SELECT scope,row_number() OVER (ORDER BY scope) AS position FROM vaults WHERE account_id=$1) UPDATE vaults v SET change_sequence=$2+n.position FROM numbered n WHERE v.account_id=$1 AND v.scope=n.scope`, device.AccountID, sequence); err != nil {
			return err
		}
		if _, err = tx.Exec(r.Context(), `UPDATE accounts SET vault_sequence=vault_sequence+$2 WHERE id=$1`, device.AccountID, count); err != nil {
			return err
		}

		recovery, _ := json.Marshal(input.RecoveryWrapped)
		if _, err = tx.Exec(r.Context(), `UPDATE accounts SET recovery_wrapped_key=$2,recovery_public_key=$3 WHERE id=$1`, device.AccountID, recovery, input.RecoveryPublic); err != nil {
			return err
		}
	} else if input.RecoveryWrapped != nil {
		return problem(400, "migration_required")
	}
	wrapped, _ := json.Marshal(input.Wrapped)
	if _, err = tx.Exec(r.Context(), `UPDATE accounts SET record=$1,wrapped_key=$2 WHERE id=$3`, wire, wrapped, device.AccountID); err != nil {
		return err
	}
	if _, err = tx.Exec(r.Context(), `UPDATE devices SET revoked_at=clock_timestamp() WHERE account_id=$1 AND revoked_at IS NULL`, device.AccountID); err != nil {
		return err
	}
	if _, err = tx.Exec(r.Context(), `DELETE FROM challenges WHERE account_id=$1`, device.AccountID); err != nil {
		return err
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	write(w, 200, map[string]string{"status": "password_updated_sign_in_again"})
	return nil
}
