package backup

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Layout struct {
	Database string
	BlobDir  string
}

type Service struct {
	db      *sql.DB
	layout  Layout
	version string
	mu      sync.Mutex
	now     func() time.Time
}

type Manifest struct {
	FormatVersion int            `json:"format_version"`
	ArcaVersion   string         `json:"arca_version"`
	SchemaVersion int            `json:"schema_version"`
	InstanceID    string         `json:"instance_id"`
	CreatedAt     time.Time      `json:"created_at"`
	Database      ManifestFile   `json:"database"`
	Blobs         []ManifestBlob `json:"blobs"`
	TotalBytes    int64          `json:"total_bytes"`
	Notes         []string       `json:"notes"`
}

type ManifestFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type ManifestBlob struct {
	ID         string `json:"id"`
	StorageKey string `json:"storage_key"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
	Path       string `json:"path"`
}

func New(db *sql.DB, layout Layout, version string) *Service {
	return &Service{db: db, layout: layout, version: version, now: time.Now}
}

func (s *Service) Create(ctx context.Context, destination string) (Manifest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return Manifest{}, errors.New("backup database is required")
	}
	abs, err := filepath.Abs(destination)
	if err != nil {
		return Manifest{}, err
	}
	if _, err := os.Stat(abs); !errors.Is(err, fs.ErrNotExist) {
		if err == nil {
			return Manifest{}, fmt.Errorf("backup destination already exists: %s", abs)
		}
		return Manifest{}, err
	}
	parent := filepath.Dir(abs)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return Manifest{}, err
	}
	temporary, err := os.MkdirTemp(parent, ".arca-backup-*")
	if err != nil {
		return Manifest{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(temporary)
		}
	}()
	databasePath := filepath.Join(temporary, "database.sqlite3")
	if _, err := s.db.ExecContext(ctx, `VACUUM INTO `+sqliteLiteral(databasePath)); err != nil {
		return Manifest{}, fmt.Errorf("create SQLite snapshot: %w", err)
	}
	snapshot, err := sql.Open("sqlite", databasePath+"?mode=ro")
	if err != nil {
		return Manifest{}, err
	}
	defer snapshot.Close()
	manifest := Manifest{
		FormatVersion: 1,
		ArcaVersion:   s.version,
		CreatedAt:     s.now().UTC(),
		Notes: []string{
			"This backup contains plaintext user files.",
			"WorkOS credentials, session keys, staging uploads, and preview cache are excluded.",
		},
	}
	_ = snapshot.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&manifest.SchemaVersion)
	_ = snapshot.QueryRowContext(ctx, `SELECT instance_id FROM instance_settings WHERE singleton = 1`).Scan(&manifest.InstanceID)
	manifest.Database, err = hashFile(databasePath, "database.sqlite3")
	if err != nil {
		return Manifest{}, err
	}
	manifest.TotalBytes = manifest.Database.Size
	rows, err := snapshot.QueryContext(ctx, `SELECT id, storage_key, size_bytes, sha256 FROM blobs WHERE state = 'ready' AND ref_count > 0 ORDER BY id`)
	if err != nil {
		return Manifest{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var blob ManifestBlob
		if err := rows.Scan(&blob.ID, &blob.StorageKey, &blob.Size, &blob.SHA256); err != nil {
			return Manifest{}, err
		}
		relative, err := blobRelativePath(blob.StorageKey)
		if err != nil {
			return Manifest{}, fmt.Errorf("invalid blob %s: %w", blob.ID, err)
		}
		blob.Path = filepath.ToSlash(filepath.Join("blobs", relative))
		source := filepath.Join(s.layout.BlobDir, relative)
		target := filepath.Join(temporary, filepath.FromSlash(blob.Path))
		if err := copyVerified(source, target, blob.Size, blob.SHA256); err != nil {
			return Manifest{}, fmt.Errorf("copy blob %s: %w", blob.ID, err)
		}
		manifest.Blobs = append(manifest.Blobs, blob)
		manifest.TotalBytes += blob.Size
	}
	if err := rows.Err(); err != nil {
		return Manifest{}, err
	}
	if err := writeJSON(filepath.Join(temporary, "manifest.json"), manifest); err != nil {
		return Manifest{}, err
	}
	if err := syncTree(temporary); err != nil {
		return Manifest{}, err
	}
	if err := os.Rename(temporary, abs); err != nil {
		return Manifest{}, err
	}
	committed = true
	return manifest, nil
}

func Verify(ctx context.Context, source string) (Manifest, error) {
	select {
	case <-ctx.Done():
		return Manifest{}, ctx.Err()
	default:
	}
	manifest, err := readManifest(filepath.Join(source, "manifest.json"))
	if err != nil {
		return Manifest{}, err
	}
	if manifest.FormatVersion != 1 {
		return Manifest{}, fmt.Errorf("unsupported backup format %d", manifest.FormatVersion)
	}
	if err := verifyManifestFile(filepath.Join(source, manifest.Database.Path), manifest.Database.Size, manifest.Database.SHA256); err != nil {
		return Manifest{}, fmt.Errorf("database: %w", err)
	}
	seen := make(map[string]struct{}, len(manifest.Blobs))
	for _, blob := range manifest.Blobs {
		if _, exists := seen[blob.ID]; exists {
			return Manifest{}, fmt.Errorf("duplicate blob %s", blob.ID)
		}
		seen[blob.ID] = struct{}{}
		path := filepath.Join(source, filepath.FromSlash(blob.Path))
		if !within(source, path) {
			return Manifest{}, fmt.Errorf("blob path escapes backup: %s", blob.Path)
		}
		if err := verifyManifestFile(path, blob.Size, blob.SHA256); err != nil {
			return Manifest{}, fmt.Errorf("blob %s: %w", blob.ID, err)
		}
	}
	return manifest, nil
}

func Restore(ctx context.Context, source string, destination Layout) (Manifest, error) {
	manifest, err := Verify(ctx, source)
	if err != nil {
		return Manifest{}, err
	}
	for _, target := range []string{destination.Database, destination.BlobDir} {
		if _, err := os.Stat(target); !errors.Is(err, fs.ErrNotExist) {
			if err == nil {
				return Manifest{}, fmt.Errorf("restore target is not empty: %s", target)
			}
			return Manifest{}, err
		}
	}
	if err := os.MkdirAll(filepath.Dir(destination.Database), 0o700); err != nil {
		return Manifest{}, err
	}
	if err := os.MkdirAll(destination.BlobDir, 0o700); err != nil {
		return Manifest{}, err
	}
	if err := copyVerified(filepath.Join(source, manifest.Database.Path), destination.Database, manifest.Database.Size, manifest.Database.SHA256); err != nil {
		return Manifest{}, err
	}
	for _, blob := range manifest.Blobs {
		relative, err := blobRelativePath(blob.StorageKey)
		if err != nil {
			return Manifest{}, err
		}
		if err := copyVerified(filepath.Join(source, filepath.FromSlash(blob.Path)), filepath.Join(destination.BlobDir, relative), blob.Size, blob.SHA256); err != nil {
			return Manifest{}, err
		}
	}
	return manifest, nil
}

func hashFile(path, relative string) (ManifestFile, error) {
	file, err := os.Open(path)
	if err != nil {
		return ManifestFile{}, err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return ManifestFile{}, err
	}
	return ManifestFile{Path: relative, Size: size, SHA256: hex.EncodeToString(hash.Sum(nil))}, nil
}

func copyVerified(source, destination string, expectedSize int64, expectedHash string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	cleanup := func() {
		_ = output.Close()
		_ = os.Remove(destination)
	}
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(output, hash), input)
	if err != nil {
		cleanup()
		return err
	}
	if written != expectedSize || !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), expectedHash) {
		cleanup()
		return errors.New("size or checksum mismatch")
	}
	if err := output.Sync(); err != nil {
		cleanup()
		return err
	}
	return output.Close()
}

func verifyManifestFile(path string, size int64, hash string) error {
	actual, err := hashFile(path, "")
	if err != nil {
		return err
	}
	if actual.Size != size || !strings.EqualFold(actual.SHA256, hash) {
		return errors.New("size or checksum mismatch")
	}
	return nil
}

func blobRelativePath(key string) (string, error) {
	if len(key) < 4 || strings.ContainsAny(key, `/\\`) || strings.Contains(key, "..") {
		return "", errors.New("unsafe storage key")
	}
	for _, char := range key {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-' || char == '_') {
			return "", errors.New("unsafe storage key")
		}
	}
	return filepath.Join(key[:2], key[2:4], key), nil
}

func readManifest(path string) (Manifest, error) {
	file, err := os.Open(path)
	if err != nil {
		return Manifest{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func writeJSON(path string, value any) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func syncTree(root string) error {
	var dirs []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			dirs = append(dirs, path)
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		err = file.Sync()
		_ = file.Close()
		return err
	})
	if err != nil {
		return err
	}
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
	for _, dir := range dirs {
		file, err := os.Open(dir)
		if err != nil {
			return err
		}
		err = file.Sync()
		_ = file.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func sqliteLiteral(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }

func within(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
