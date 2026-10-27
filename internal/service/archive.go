package service

import (
	"net/http"
	"strconv"
	"strings"
)

func (s *Service) archiveChanges(w http.ResponseWriter, r *http.Request) error {
	device, err := s.authenticate(r)
	if err != nil {
		return err
	}
	scope := r.PathValue("scope")
	if scope != "full" && !strings.HasPrefix(scope, "server:") {
		return problem(400, "invalid_vault_scope")
	}
	if err = vaultScope(device, scope); err != nil {
		return err
	}
	after, err := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	if err != nil || after < 0 || after > 1<<52 {
		return problem(400, "invalid_revision")
	}
	var current int64
	if err = s.Pool.QueryRow(r.Context(), `SELECT vault_sequence FROM accounts WHERE id=$1`, device.AccountID).Scan(&current); err != nil {
		return err
	}
	if after > current {
		return problem(409, "archive_revision_rollback")
	}
	through := current
	if raw := r.URL.Query().Get("through"); raw != "" {
		through, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || through < after || through > current {
			return problem(400, "invalid_revision")
		}
	}
	prefix := "archive-chunk:" + scope + ":"
	rows, err := s.Pool.Query(r.Context(), `SELECT scope,revision,change_sequence FROM vaults WHERE account_id=$1 AND starts_with(scope,$2) AND change_sequence>$3 AND change_sequence<=$4 ORDER BY change_sequence LIMIT 200`, device.AccountID, prefix, after, through)
	if err != nil {
		return err
	}
	defer rows.Close()
	type entry struct {
		Scope    string `json:"scope"`
		Revision int64  `json:"revision"`
		Sequence int64  `json:"sequence"`
	}
	entries := []entry{}
	for rows.Next() {
		var item entry
		if err = rows.Scan(&item.Scope, &item.Revision, &item.Sequence); err != nil {
			return err
		}
		entries = append(entries, item)
	}
	if err = rows.Err(); err != nil {
		return err
	}
	next := through
	if len(entries) == 200 {
		next = entries[len(entries)-1].Sequence
	}
	write(w, 200, map[string]any{"entries": entries, "cursor": next, "through": through})
	return nil
}
