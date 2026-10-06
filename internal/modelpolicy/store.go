// Package modelpolicy stores versioned group-to-model grants shared by all replicas.
package modelpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"sort"
	"strings"
	"time"
	"unicode"
)

var ErrConflict = errors.New("policy revision changed")
var ErrInvalid = errors.New("invalid explicit model policy")

type Snapshot struct {
	Revision int64
	Rules    map[string][]string
}
type Audit struct {
	At            time.Time
	Subject       string
	Before, After map[string][]string
}
type Store struct{ Pool *pgxpool.Pool }

func Validate(rules map[string][]string) error {
	if rules == nil || len(rules) > 500 {
		return ErrInvalid
	}
	valid := func(s string) bool {
		return len(s) > 0 && len(s) <= 256 && s == strings.TrimSpace(s) && s != "*" && !strings.ContainsAny(s, ",") && !strings.ContainsFunc(s, unicode.IsControl)
	}
	for group, models := range rules {
		if !valid(group) || len(models) == 0 || len(models) > 200 {
			return ErrInvalid
		}
		seen := map[string]bool{}
		for _, model := range models {
			if !valid(model) || seen[model] {
				return ErrInvalid
			}
			seen[model] = true
		}
	}
	return nil
}
func (s *Store) Migrate(ctx context.Context) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(742901020)`); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS portico_model_policy (id integer PRIMARY KEY CHECK(id=1), revision bigint NOT NULL, rules jsonb NOT NULL);
 CREATE TABLE IF NOT EXISTS portico_model_policy_audit (revision bigint PRIMARY KEY, at timestamptz NOT NULL DEFAULT now(), subject text NOT NULL, before_rules jsonb NOT NULL, after_rules jsonb NOT NULL);`)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Seed only initializes a new database. A restart never restores revoked grants.
func (s *Store) Seed(ctx context.Context, rules map[string][]string) error {
	if rules == nil {
		rules = map[string][]string{}
	}
	if err := Validate(rules); err != nil {
		return err
	}
	data, err := json.Marshal(rules)
	if err != nil {
		return err
	}
	_, err = s.Pool.Exec(ctx, `INSERT INTO portico_model_policy(id,revision,rules) VALUES(1,1,$1) ON CONFLICT(id) DO NOTHING`, data)
	return err
}
func (s *Store) Read(ctx context.Context) (Snapshot, error) {
	var out Snapshot
	var data []byte
	err := s.Pool.QueryRow(ctx, `SELECT revision,rules FROM portico_model_policy WHERE id=1`).Scan(&out.Revision, &data)
	if err != nil {
		return out, err
	}
	if err = json.Unmarshal(data, &out.Rules); err != nil {
		return out, err
	}
	return out, Validate(out.Rules)
}
func (s *Store) Allowed(ctx context.Context, groups []string) (map[string]bool, error) {
	snapshot, err := s.Read(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, g := range groups {
		for _, m := range snapshot.Rules[g] {
			out[m] = true
		}
	}
	return out, nil
}
func (s *Store) Update(ctx context.Context, revision int64, subject string, rules map[string][]string) error {
	if subject == "" || revision < 1 {
		return ErrInvalid
	}
	if err := Validate(rules); err != nil {
		return err
	}
	data, err := json.Marshal(rules)
	if err != nil {
		return err
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var before []byte
	var current int64
	if err = tx.QueryRow(ctx, `SELECT revision,rules FROM portico_model_policy WHERE id=1 FOR UPDATE`).Scan(&current, &before); err != nil {
		return err
	}
	if current != revision {
		return ErrConflict
	}
	if _, err = tx.Exec(ctx, `UPDATE portico_model_policy SET revision=revision+1,rules=$1 WHERE id=1`, data); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO portico_model_policy_audit(revision,subject,before_rules,after_rules) VALUES($1,$2,$3,$4)`, revision+1, subject, before, data); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (s *Store) History(ctx context.Context) ([]Audit, error) {
	rows, err := s.Pool.Query(ctx, `SELECT at,subject,before_rules,after_rules FROM portico_model_policy_audit ORDER BY revision DESC LIMIT 50`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Audit{}
	for rows.Next() {
		var a Audit
		var b, c []byte
		if err = rows.Scan(&a.At, &a.Subject, &b, &c); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(b, &a.Before); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(c, &a.After); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
func SortedModels(allowed map[string]bool) []string {
	out := []string{}
	for model := range allowed {
		out = append(out, model)
	}
	sort.Strings(out)
	return out
}
