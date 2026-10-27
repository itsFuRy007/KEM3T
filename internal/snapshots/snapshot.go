package snapshots

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var ErrNotFound = errors.New("snapshot not found")

type Snapshot struct {
	Target    string    `json:"target"`
	Collected time.Time `json:"collected_at"`
	Addresses []string  `json:"addresses"`
}

func New(target string, addresses []string) (Snapshot, error) {
	target = strings.ToLower(strings.TrimSpace(target))
	if target == "" {
		return Snapshot{}, fmt.Errorf("snapshot target is required")
	}

	normalized, err := normalizeAddresses(addresses)
	if err != nil {
		return Snapshot{}, err
	}

	return Snapshot{
		Target:    target,
		Collected: time.Now().UTC(),
		Addresses: normalized,
	}, nil
}

func normalizeAddresses(addresses []string) ([]string, error) {
	unique := make(map[string]struct{}, len(addresses))

	for _, address := range addresses {
		ip := net.ParseIP(strings.TrimSpace(address))
		if ip == nil {
			return nil, fmt.Errorf("invalid IP address %q", address)
		}
		unique[ip.String()] = struct{}{}
	}

	result := make([]string, 0, len(unique))
	for address := range unique {
		result = append(result, address)
	}
	sort.Strings(result)

	return result, nil
}

func (s Snapshot) Validate() error {
	if strings.TrimSpace(s.Target) == "" {
		return fmt.Errorf("snapshot target is required")
	}
	if s.Collected.IsZero() {
		return fmt.Errorf("snapshot collection time is required")
	}

	normalized, err := normalizeAddresses(s.Addresses)
	if err != nil {
		return err
	}
	if len(normalized) != len(s.Addresses) {
		return fmt.Errorf("snapshot addresses must be unique")
	}
	for i := range normalized {
		if normalized[i] != s.Addresses[i] {
			return fmt.Errorf("snapshot addresses must be normalized and sorted")
		}
	}

	return nil
}

type Store struct {
	Dir string
}

func NewStore(dir string) (*Store, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, fmt.Errorf("snapshot directory is required")
	}
	return &Store{Dir: dir}, nil
}

func (s *Store) Save(snapshot Snapshot) error {
	if s == nil || strings.TrimSpace(s.Dir) == "" {
		return fmt.Errorf("snapshot store directory is required")
	}
	if err := snapshot.Validate(); err != nil {
		return fmt.Errorf("invalid snapshot: %w", err)
	}

	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("encode snapshot: %w", err)
	}
	data = append(data, '\n')

	if err := os.MkdirAll(s.Dir, 0750); err != nil {
		return fmt.Errorf("create snapshot directory: %w", err)
	}

	temp, err := os.CreateTemp(s.Dir, ".snapshot-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary snapshot: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)

	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return fmt.Errorf("write snapshot: %w", err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return fmt.Errorf("sync snapshot: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close snapshot: %w", err)
	}
	if err := os.Rename(tempPath, s.path(snapshot.Target)); err != nil {
		return fmt.Errorf("replace snapshot: %w", err)
	}

	return nil
}

func (s *Store) Load(target string) (Snapshot, error) {
	if s == nil || strings.TrimSpace(s.Dir) == "" {
		return Snapshot{}, fmt.Errorf("snapshot store directory is required")
	}
	target = strings.ToLower(strings.TrimSpace(target))
	if target == "" {
		return Snapshot{}, fmt.Errorf("snapshot target is required")
	}

	data, err := os.ReadFile(s.path(target))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Snapshot{}, fmt.Errorf("%w: %s", ErrNotFound, target)
		}
		return Snapshot{}, fmt.Errorf("read snapshot: %w", err)
	}

	var snapshot Snapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("decode snapshot: %w", err)
	}
	if err := snapshot.Validate(); err != nil {
		return Snapshot{}, fmt.Errorf("invalid stored snapshot: %w", err)
	}
	if !strings.EqualFold(snapshot.Target, target) {
		return Snapshot{}, fmt.Errorf("stored snapshot target does not match requested target")
	}

	return snapshot, nil
}

func (s *Store) path(target string) string {
	return filepath.Join(s.Dir, strings.ToLower(strings.TrimSpace(target))+".json")
}
