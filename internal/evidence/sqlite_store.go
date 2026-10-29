package evidence

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	_ "modernc.org/sqlite"
	"net"
	"path/filepath"
	"strings"
	"time"
)

// SQLiteStore persists evidence and observations in a SQLite database.
type SQLiteStore struct {
	db *sql.DB
}

// OpenSQLiteStore opens or creates a SQLite database and initializes its schema.
func OpenSQLiteStore(path string) (*SQLiteStore, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("database path is required")
	}
	if path != ":memory:" && !strings.HasPrefix(path, "file:") {
		absolutePath, err := filepath.Abs(path)
		if err != nil {
			return nil, fmt.Errorf("resolve database path: %w", err)
		}
		path = absolutePath
	}
	dsn := path
	if path != ":memory:" && !strings.HasPrefix(path, "file:") {
		dsn = "file:" + filepath.ToSlash(path)
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open SQLite database: %w", err)
	}
	// Keep one connection so SQLite connection settings remain consistent.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	store := &SQLiteStore{db: db}
	if err := store.initialize(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}
func (s *SQLiteStore) initialize(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `PRAGMA foreign_keys = ON`); err != nil {
		return fmt.Errorf("enable SQLite foreign keys: %w", err)
	}
	const schema = `
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    entity_id TEXT NOT NULL,
    type TEXT NOT NULL,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS observations (
    id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL,
    source TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    event_ids_json TEXT NOT NULL,
    FOREIGN KEY (evidence_id) REFERENCES evidence(id)
);
CREATE INDEX IF NOT EXISTS idx_observations_evidence_time
ON observations(evidence_id, observed_at, id);

CREATE TABLE IF NOT EXISTS collection_runs (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    event_count INTEGER NOT NULL DEFAULT 0,
    address_count INTEGER NOT NULL DEFAULT 0,
    error_message TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_collection_runs_target_started
ON collection_runs(target, started_at DESC, id DESC);
`
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("initialize evidence schema: %w", err)
	}
	return nil
}

// Close closes the database connection.
func (s *SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// SaveEvidence inserts an evidence record.
func (s *SQLiteStore) SaveEvidence(ctx context.Context, e Evidence) error {
	if err := e.Validate(); err != nil {
		return fmt.Errorf("validate evidence: %w", err)
	}
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO evidence (id, entity_id, type, value) VALUES (?, ?, ?, ?)`,
		e.ID,
		e.EntityID,
		string(e.Type),
		e.Value,
	)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique constraint failed") {
			return ErrEvidenceExists
		}
		return fmt.Errorf("save evidence: %w", err)
	}
	return nil
}

// LoadEvidence returns an evidence record by ID.
func (s *SQLiteStore) LoadEvidence(ctx context.Context, id string) (Evidence, error) {
	var e Evidence
	var evidenceType string
	err := s.db.QueryRowContext(
		ctx,
		`SELECT id, entity_id, type, value FROM evidence WHERE id = ?`,
		strings.TrimSpace(id),
	).Scan(&e.ID, &e.EntityID, &evidenceType, &e.Value)
	if errors.Is(err, sql.ErrNoRows) {
		return Evidence{}, ErrEvidenceNotFound
	}
	if err != nil {
		return Evidence{}, fmt.Errorf("load evidence: %w", err)
	}
	e.Type = Type(evidenceType)
	return e, nil
}

// SaveObservation inserts an observation and its event references.
func (s *SQLiteStore) SaveObservation(ctx context.Context, o Observation) error {
	if err := o.Validate(); err != nil {
		return fmt.Errorf("validate observation: %w", err)
	}
	eventIDs, err := json.Marshal(o.EventIDs)
	if err != nil {
		return fmt.Errorf("encode observation event IDs: %w", err)
	}
	_, err = s.db.ExecContext(
		ctx,
		`INSERT INTO observations
		 (id, evidence_id, source, observed_at, event_ids_json)
		 VALUES (?, ?, ?, ?, ?)`,
		o.ID,
		o.EvidenceID,
		o.Source,
		o.ObservedAt.UTC().Format(time.RFC3339Nano),
		string(eventIDs),
	)
	if err != nil {
		message := strings.ToLower(err.Error())
		if strings.Contains(message, "unique constraint failed") {
			return ErrObservationExists
		}
		if strings.Contains(message, "foreign key constraint failed") {
			return ErrEvidenceNotFound
		}
		return fmt.Errorf("save observation: %w", err)
	}
	return nil
}


 // SaveBatch atomically persists evidence and observations in one SQLite
 // transaction. It validates and encodes records before opening the transaction,
 // then reuses prepared statements to avoid repeated statement compilation.
 // If any record fails, the entire batch is rolled back.
 func (s *SQLiteStore) SaveBatch(ctx context.Context, evidenceRecords []Evidence, observations []Observation) error {
 	if len(evidenceRecords) == 0 && len(observations) == 0 {
 		return nil
 	}
 	for _, record := range evidenceRecords {
 		if err := record.Validate(); err != nil {
 			return fmt.Errorf("validate evidence %q: %w", record.ID, err)
 		}
 	}
 	type encodedObservation struct {
 		record Observation
 		eventIDs string
 	}
 	encoded := make([]encodedObservation, 0, len(observations))
 	for _, record := range observations {
 		if err := record.Validate(); err != nil {
 			return fmt.Errorf("validate observation %q: %w", record.ID, err)
 		}
 		eventIDs, err := json.Marshal(record.EventIDs)
 		if err != nil {
 			return fmt.Errorf("encode observation %q event IDs: %w", record.ID, err)
 		}
 		encoded = append(encoded, encodedObservation{record: record, eventIDs: string(eventIDs)})
 	}
 	tx, err := s.db.BeginTx(ctx, nil)
 	if err != nil {
 		return fmt.Errorf("begin evidence batch transaction: %w", err)
 	}
 	defer tx.Rollback()
 	evidenceStmt, err := tx.PrepareContext(ctx, `INSERT INTO evidence (id, entity_id, type, value) VALUES (?, ?, ?, ?)`)
 	if err != nil {
 		return fmt.Errorf("prepare evidence batch insert: %w", err)
 	}
 	defer evidenceStmt.Close()
 	observationStmt, err := tx.PrepareContext(ctx, `INSERT INTO observations
 		(id, evidence_id, source, observed_at, event_ids_json) VALUES (?, ?, ?, ?, ?)`)
 	if err != nil {
 		return fmt.Errorf("prepare observation batch insert: %w", err)
 	}
 	defer observationStmt.Close()
 	for _, record := range evidenceRecords {
 		_, err := evidenceStmt.ExecContext(ctx, record.ID, record.EntityID, string(record.Type), record.Value)
 		if err != nil {
 			if strings.Contains(strings.ToLower(err.Error()), "unique constraint failed") {
 				return ErrEvidenceExists
 			}
 			return fmt.Errorf("save evidence batch record %q: %w", record.ID, err)
 		}
 	}
 	for _, item := range encoded {
 		record := item.record
 		_, err := observationStmt.ExecContext(ctx, record.ID, record.EvidenceID, record.Source,
 			record.ObservedAt.UTC().Format(time.RFC3339Nano), item.eventIDs)
 		if err != nil {
 			message := strings.ToLower(err.Error())
 			if strings.Contains(message, "unique constraint failed") {
 				return ErrObservationExists
 			}
 			if strings.Contains(message, "foreign key constraint failed") {
 				return ErrEvidenceNotFound
 			}
 			return fmt.Errorf("save observation batch record %q: %w", record.ID, err)
 		}
 	}
 	if err := tx.Commit(); err != nil {
 		return fmt.Errorf("commit evidence batch transaction: %w", err)
 	}
 	return nil
 }

// LoadObservation returns an observation by ID.
func (s *SQLiteStore) LoadObservation(ctx context.Context, id string) (Observation, error) {
	var o Observation
	var observedAt string
	var eventIDsJSON string
	err := s.db.QueryRowContext(
		ctx,
		`SELECT id, evidence_id, source, observed_at, event_ids_json
		 FROM observations WHERE id = ?`,
		strings.TrimSpace(id),
	).Scan(
		&o.ID,
		&o.EvidenceID,
		&o.Source,
		&observedAt,
		&eventIDsJSON,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Observation{}, ErrObservationNotFound
	}
	if err != nil {
		return Observation{}, fmt.Errorf("load observation: %w", err)
	}
	o.ObservedAt, err = time.Parse(time.RFC3339Nano, observedAt)
	if err != nil {
		return Observation{}, fmt.Errorf("parse observation timestamp: %w", err)
	}
	if err := json.Unmarshal([]byte(eventIDsJSON), &o.EventIDs); err != nil {
		return Observation{}, fmt.Errorf("decode observation event IDs: %w", err)
	}
	return o, nil
}

// LoadAll loads every evidence record and observation from the database.
func (s *SQLiteStore) LoadAll(ctx context.Context) ([]Evidence, []Observation, error) {
	evidenceRows, err := s.db.QueryContext(
		ctx,
		`SELECT id, entity_id, type, value FROM evidence ORDER BY id`,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("query evidence: %w", err)
	}
	var allEvidence []Evidence
	for evidenceRows.Next() {
		var e Evidence
		var evidenceType string
		if err := evidenceRows.Scan(&e.ID, &e.EntityID, &evidenceType, &e.Value); err != nil {
			_ = evidenceRows.Close()
			return nil, nil, fmt.Errorf("read evidence: %w", err)
		}
		e.Type = Type(evidenceType)
		allEvidence = append(allEvidence, e)
	}
	if err := evidenceRows.Err(); err != nil {
		_ = evidenceRows.Close()
		return nil, nil, fmt.Errorf("iterate evidence: %w", err)
	}
	if err := evidenceRows.Close(); err != nil {
		return nil, nil, fmt.Errorf("close evidence rows: %w", err)
	}
	observationRows, err := s.db.QueryContext(
		ctx,
		`SELECT id, evidence_id, source, observed_at, event_ids_json
		 FROM observations ORDER BY observed_at, id`,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("query observations: %w", err)
	}
	defer observationRows.Close()
	var allObservations []Observation
	for observationRows.Next() {
		var o Observation
		var observedAt, eventIDsJSON string
		if err := observationRows.Scan(
			&o.ID,
			&o.EvidenceID,
			&o.Source,
			&observedAt,
			&eventIDsJSON,
		); err != nil {
			return nil, nil, fmt.Errorf("read observation: %w", err)
		}
		o.ObservedAt, err = time.Parse(time.RFC3339Nano, observedAt)
		if err != nil {
			return nil, nil, fmt.Errorf("parse observation timestamp: %w", err)
		}
		if err := json.Unmarshal([]byte(eventIDsJSON), &o.EventIDs); err != nil {
			return nil, nil, fmt.Errorf("decode observation event IDs: %w", err)
		}
		allObservations = append(allObservations, o)
	}
	if err := observationRows.Err(); err != nil {
		return nil, nil, fmt.Errorf("iterate observations: %w", err)
	}
	return allEvidence, allObservations, nil
}

// SaveCollectionRun persists a new collection run.
func (s *SQLiteStore) SaveCollectionRun(ctx context.Context, r CollectionRun) error {
	if err := r.Validate(); err != nil {
		return fmt.Errorf("validate collection run: %w", err)
	}

	finishedAt := ""
	if !r.FinishedAt.IsZero() {
		finishedAt = r.FinishedAt.UTC().Format(time.RFC3339Nano)
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO collection_runs
		(id, target, started_at, finished_at, status, event_count, address_count, error_message)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID,
		strings.ToLower(strings.TrimSpace(r.Target)),
		r.StartedAt.UTC().Format(time.RFC3339Nano),
		finishedAt,
		string(r.Status),
		r.EventCount,
		r.AddressCount,
		r.ErrorMessage,
	)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique constraint failed") {
			return fmt.Errorf("collection run %q already exists", r.ID)
		}
		return fmt.Errorf("save collection run: %w", err)
	}
	return nil
}

// UpdateCollectionRun updates an existing collection run.
func (s *SQLiteStore) UpdateCollectionRun(ctx context.Context, r CollectionRun) error {
	if err := r.Validate(); err != nil {
		return fmt.Errorf("validate collection run: %w", err)
	}

	finishedAt := ""
	if !r.FinishedAt.IsZero() {
		finishedAt = r.FinishedAt.UTC().Format(time.RFC3339Nano)
	}

	result, err := s.db.ExecContext(ctx, `
		UPDATE collection_runs
		SET target = ?, started_at = ?, finished_at = ?, status = ?,
		    event_count = ?, address_count = ?, error_message = ?
		WHERE id = ?`,
		strings.ToLower(strings.TrimSpace(r.Target)),
		r.StartedAt.UTC().Format(time.RFC3339Nano),
		finishedAt,
		string(r.Status),
		r.EventCount,
		r.AddressCount,
		r.ErrorMessage,
		strings.TrimSpace(r.ID),
	)
	if err != nil {
		return fmt.Errorf("update collection run: %w", err)
	}

	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check collection run update: %w", err)
	}
	if n == 0 {
		var exists int
		err := s.db.QueryRowContext(
			ctx, `SELECT 1 FROM collection_runs WHERE id = ?`, strings.TrimSpace(r.ID),
		).Scan(&exists)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("collection run %q not found", r.ID)
		}
		if err != nil {
			return fmt.Errorf("check collection run existence: %w", err)
		}
	}
	return nil
}

// LoadCollectionRun retrieves one collection run by ID.
func (s *SQLiteStore) LoadCollectionRun(ctx context.Context, id string) (CollectionRun, error) {
	var r CollectionRun
	var startedAt, finishedAt, status string

	err := s.db.QueryRowContext(ctx, `
		SELECT id, target, started_at, finished_at, status,
		       event_count, address_count, error_message
		FROM collection_runs WHERE id = ?`,
		strings.TrimSpace(id),
	).Scan(
		&r.ID, &r.Target, &startedAt, &finishedAt, &status,
		&r.EventCount, &r.AddressCount, &r.ErrorMessage,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return CollectionRun{}, fmt.Errorf("collection run %q not found", id)
	}
	if err != nil {
		return CollectionRun{}, fmt.Errorf("load collection run: %w", err)
	}

	r.StartedAt, err = time.Parse(time.RFC3339Nano, startedAt)
	if err != nil {
		return CollectionRun{}, fmt.Errorf("parse collection run start time: %w", err)
	}
	if finishedAt != "" {
		r.FinishedAt, err = time.Parse(time.RFC3339Nano, finishedAt)
		if err != nil {
			return CollectionRun{}, fmt.Errorf("parse collection run finish time: %w", err)
		}
	}
	r.Status = CollectionRunStatus(status)
	if err := r.Validate(); err != nil {
		return CollectionRun{}, fmt.Errorf("invalid stored collection run: %w", err)
	}
	return r, nil
}

// LoadCollectionRuns retrieves collection runs, newest first.
func (s *SQLiteStore) LoadCollectionRuns(ctx context.Context, target string) ([]CollectionRun, error) {
	query := `
		SELECT id, target, started_at, finished_at, status,
		       event_count, address_count, error_message
		FROM collection_runs`
	args := []any{}

	if strings.TrimSpace(target) != "" {
		query += ` WHERE target = ?`
		args = append(args, strings.ToLower(strings.TrimSpace(target)))
	}
	query += ` ORDER BY started_at DESC, id DESC`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query collection runs: %w", err)
	}
	defer rows.Close()

	var result []CollectionRun
	for rows.Next() {
		var r CollectionRun
		var startedAt, finishedAt, status string
		if err := rows.Scan(
			&r.ID, &r.Target, &startedAt, &finishedAt, &status,
			&r.EventCount, &r.AddressCount, &r.ErrorMessage,
		); err != nil {
			return nil, fmt.Errorf("read collection run: %w", err)
		}
		r.StartedAt, err = time.Parse(time.RFC3339Nano, startedAt)
		if err != nil {
			return nil, fmt.Errorf("parse collection run start time: %w", err)
		}
		if finishedAt != "" {
			r.FinishedAt, err = time.Parse(time.RFC3339Nano, finishedAt)
			if err != nil {
				return nil, fmt.Errorf("parse collection run finish time: %w", err)
			}
		}
		r.Status = CollectionRunStatus(status)
		if err := r.Validate(); err != nil {
			return nil, fmt.Errorf("invalid stored collection run %q: %w", r.ID, err)
		}
		result = append(result, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate collection runs: %w", err)
	}
	return result, nil
}

// NormalizeEvidenceAddress canonicalizes an IP address for DNS evidence.
func NormalizeEvidenceAddress(value string) string {
	value = strings.TrimSpace(value)
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	return value
}
