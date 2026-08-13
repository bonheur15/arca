package uploads

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type LocalStorage struct {
	root       string
	blobs      string
	staging    string
	quarantine string
}

func NewLocalStorage(dataDir string) (*LocalStorage, error) {
	if strings.TrimSpace(dataDir) == "" {
		return nil, errors.New("storage data directory is required")
	}
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, fmt.Errorf("resolve storage root: %w", err)
	}
	s := &LocalStorage{
		root:       abs,
		blobs:      filepath.Join(abs, "storage", "blobs"),
		staging:    filepath.Join(abs, "storage", "staging"),
		quarantine: filepath.Join(abs, "storage", "quarantine"),
	}
	for _, dir := range []string{s.blobs, s.staging, s.quarantine} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create storage directory: %w", err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return nil, fmt.Errorf("secure storage directory: %w", err)
		}
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("storage path %q must be a real directory", dir)
		}
	}
	stagingInfo, err := os.Stat(s.staging)
	if err != nil {
		return nil, err
	}
	blobInfo, err := os.Stat(s.blobs)
	if err != nil {
		return nil, err
	}
	stagingStat, ok1 := stagingInfo.Sys().(*syscall.Stat_t)
	blobStat, ok2 := blobInfo.Sys().(*syscall.Stat_t)
	if ok1 && ok2 && stagingStat.Dev != blobStat.Dev {
		return nil, errors.New("blob and staging directories must be on the same filesystem")
	}
	return s, nil
}

func opaqueKey(value string) error {
	if value == "" || filepath.Base(value) != value || strings.ContainsAny(value, `/\\\x00`) {
		return errors.New("invalid opaque storage key")
	}
	return nil
}

func (s *LocalStorage) stagingPath(id string) (string, error) {
	if err := opaqueKey(id); err != nil {
		return "", err
	}
	return filepath.Join(s.staging, id+".part"), nil
}

func (s *LocalStorage) blobPath(key string) (string, error) {
	if err := opaqueKey(key); err != nil {
		return "", err
	}
	if len(key) < 4 {
		return "", errors.New("blob key is too short")
	}
	return filepath.Join(s.blobs, key[:2], key[2:4], key), nil
}

func (s *LocalStorage) OpenStaging(id string) (StagingFile, error) {
	path, err := s.stagingPath(id)
	if err != nil {
		return nil, err
	}
	return openNoFollow(path, unix.O_CREAT|unix.O_WRONLY|unix.O_APPEND, 0o600)
}

func (s *LocalStorage) OpenStagingRead(id string) (io.ReadCloser, error) {
	path, err := s.stagingPath(id)
	if err != nil {
		return nil, err
	}
	return openNoFollow(path, unix.O_RDONLY, 0)
}

func (s *LocalStorage) StagingSize(id string) (int64, error) {
	path, err := s.stagingPath(id)
	if err != nil {
		return 0, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() {
		return 0, errors.New("staging path is not a regular file")
	}
	return info.Size(), nil
}

func (s *LocalStorage) TruncateStaging(id string, size int64) error {
	path, err := s.stagingPath(id)
	if err != nil {
		return err
	}
	file, err := openNoFollow(path, unix.O_WRONLY, 0)
	if err != nil {
		return err
	}
	truncateErr := file.Truncate(size)
	closeErr := file.Close()
	return errors.Join(truncateErr, closeErr)
}

func (s *LocalStorage) RemoveStaging(id string) error {
	path, err := s.stagingPath(id)
	if err != nil {
		return err
	}
	err = os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (s *LocalStorage) Finalize(id, key string) error {
	source, err := s.stagingPath(id)
	if err != nil {
		return err
	}
	destination, err := s.blobPath(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	if _, err := os.Lstat(destination); err == nil {
		return errors.New("blob key already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(source, destination); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(destination))
}

func (s *LocalStorage) OpenBlob(key string) (io.ReadCloser, error) {
	path, err := s.blobPath(key)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("blob path is not a regular file")
	}
	return openNoFollow(path, unix.O_RDONLY, 0)
}

func (s *LocalStorage) RemoveBlob(key string) error {
	path, err := s.blobPath(key)
	if err != nil {
		return err
	}
	err = os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (s *LocalStorage) QuarantineBlob(key string) error {
	path, err := s.blobPath(key)
	if err != nil {
		return err
	}
	destination := filepath.Join(s.quarantine, key)
	if err := os.Rename(path, destination); err != nil {
		return err
	}
	return syncDirectory(s.quarantine)
}

// BlobPath resolves an opaque database storage key to its local blob path. It
// validates the key and does not require the blob to exist.
func (s *LocalStorage) BlobPath(key string) (string, error) { return s.blobPath(key) }

func (s *LocalStorage) ListBlobKeys() ([]string, error) {
	var keys []string
	err := filepath.WalkDir(s.blobs, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == s.blobs {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink found in blob tree: %s", path)
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("non-regular entry found in blob tree: %s", path)
		}
		key := entry.Name()
		if err := opaqueKey(key); err != nil {
			return fmt.Errorf("invalid blob entry %q: %w", path, err)
		}
		keys = append(keys, key)
		return nil
	})
	return keys, err
}

func (s *LocalStorage) FreeBytes() (int64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(s.root, &stat); err != nil {
		return 0, err
	}
	return int64(stat.Bavail) * int64(stat.Bsize), nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) {
		return err
	}
	return nil
}

func openNoFollow(path string, flags int, mode uint32) (*os.File, error) {
	fd, err := unix.Open(path, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW, mode)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
