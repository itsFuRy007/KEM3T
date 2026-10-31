package history

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/itsFuRy007/kem3t/internal/evidence"
)

type Store struct{ Dir string }

func NewStore(dir string) (*Store, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, fmt.Errorf("history snapshot directory is required")
	}
	return &Store{Dir: dir}, nil
}

// Save atomically persists a generalized snapshot. The filename is derived
// from a hash of RunID so untrusted targets/run IDs cannot escape the store.
func (s *Store) Save(snapshot Snapshot) error {
	if s == nil || strings.TrimSpace(s.Dir) == "" {
		return fmt.Errorf("history snapshot store is required")
	}
	if err := snapshot.Validate(); err != nil {
		return fmt.Errorf("invalid history snapshot: %w", err)
	}
	if err := os.MkdirAll(s.Dir, 0750); err != nil {
		return fmt.Errorf("create history snapshot directory: %w", err)
	}
	name := snapshot.RunID
	// Hashing the run ID avoids path traversal and collisions from separators.
	sum := sha256Bytes([]byte(name))
	path := filepath.Join(s.Dir, sum+".json")
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("encode history snapshot: %w", err)
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(s.Dir, ".history-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary history snapshot: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write history snapshot: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync history snapshot: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close history snapshot: %w", err)
	}
	if err = os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace history snapshot: %w", err)
	}
	return nil
}

func (s *Store) List() ([]Snapshot, error) {
	if s == nil || strings.TrimSpace(s.Dir) == "" {
		return nil, fmt.Errorf("history snapshot store is required")
	}
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []Snapshot{}, nil
		}
		return nil, fmt.Errorf("read history snapshot directory: %w", err)
	}
	result := make([]Snapshot, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.Dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read history snapshot %q: %w", entry.Name(), err)
		}
		var snapshot Snapshot
		if err := json.Unmarshal(data, &snapshot); err != nil {
			return nil, fmt.Errorf("decode history snapshot %q: %w", entry.Name(), err)
		}
		if err := snapshot.Validate(); err != nil {
			return nil, fmt.Errorf("validate history snapshot %q: %w", entry.Name(), err)
		}
		result = append(result, snapshot)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].CollectedAt.Equal(result[j].CollectedAt) {
			return result[i].RunID < result[j].RunID
		}
		return result[i].CollectedAt.Before(result[j].CollectedAt)
	})
	return result, nil
}

func sha256Bytes(value []byte) string {
	const hex = "0123456789abcdef"
	sum := sha256.Sum256(value)
	out := make([]byte, len(sum)*2)
	for i, b := range sum {
		out[2*i] = hex[b>>4]
		out[2*i+1] = hex[b&15]
	}
	return string(out)
}

// PersistRunSnapshot builds and atomically stores the generalized snapshot for
// a successfully completed run while its evidence registry is still open.
func PersistRunSnapshot(snapshotDir string, run evidence.CollectionRun, registry *evidence.Registry, runObservations ...[]evidence.Observation) error {
	if registry == nil {
		return fmt.Errorf("evidence registry is required")
	}
	if strings.TrimSpace(snapshotDir) == "" {
		return fmt.Errorf("snapshot directory is required")
	}
	observations := registry.AllObservations()
	if len(runObservations) > 0 {
		observations = runObservations[0]
	}
	snapshot, err := BuildSnapshot(run, registry.AllEvidence(), observations)
	if err != nil {
		return err
	}
	store, err := NewStore(filepath.Join(snapshotDir, "history"))
	if err != nil {
		return err
	}
	return store.Save(snapshot)
}
