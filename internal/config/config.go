package config

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	DefaultListen  = "127.0.0.1:8080"
	DefaultDataDir = "./arca-data"
)

type FileConfig struct {
	InstanceName           string   `json:"instance_name"`
	PublicURL              string   `json:"public_url"`
	WorkOSClientID         string   `json:"workos_client_id"`
	FilesystemReserveBytes int64    `json:"filesystem_reserve_bytes"`
	TrustedProxyCIDRs      []string `json:"trusted_proxy_cidrs,omitempty"`
}

type Secrets struct {
	WorkOSAPIKey  string `json:"workos_api_key"`
	CookieKey     string `json:"cookie_key"`
	CodeHMACKey   string `json:"code_hmac_key"`
	StatusHMACKey string `json:"status_hmac_key"`
}

type Runtime struct {
	Listen   string
	DataDir  string
	TLSCert  string
	TLSKey   string
	File     FileConfig
	Secrets  Secrets
	Layout   Layout
	FromDisk bool
	// secretEnv records secrets injected by the operator so Save never copies
	// them into secrets.json. Existing persisted values are preserved instead.
	secretEnv map[string]bool
}

type Overrides struct {
	Listen  string
	DataDir string
	TLSCert string
	TLSKey  string
}

type Layout struct {
	Root        string
	ConfigFile  string
	SecretsFile string
	DatabaseDir string
	Database    string
	BlobDir     string
	StagingDir  string
	PreviewDir  string
	LockDir     string
	LockFile    string
}

func ResolveLayout(dataDir string) (Layout, error) {
	if strings.TrimSpace(dataDir) == "" {
		dataDir = DefaultDataDir
	}
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		return Layout{}, fmt.Errorf("resolve data directory: %w", err)
	}
	return Layout{
		Root:        abs,
		ConfigFile:  filepath.Join(abs, "config.json"),
		SecretsFile: filepath.Join(abs, "secrets.json"),
		DatabaseDir: filepath.Join(abs, "database"),
		Database:    filepath.Join(abs, "database", "arca.sqlite3"),
		BlobDir:     filepath.Join(abs, "storage", "blobs"),
		StagingDir:  filepath.Join(abs, "storage", "staging"),
		PreviewDir:  filepath.Join(abs, "cache", "previews"),
		LockDir:     filepath.Join(abs, "locks"),
		LockFile:    filepath.Join(abs, "locks", "instance.lock"),
	}, nil
}

func Load(overrides Overrides) (Runtime, error) {
	listen := firstNonEmpty(overrides.Listen, os.Getenv("ARCA_LISTEN"), DefaultListen)
	dataDir := firstNonEmpty(overrides.DataDir, os.Getenv("ARCA_DATA_DIR"), DefaultDataDir)
	layout, err := ResolveLayout(dataDir)
	if err != nil {
		return Runtime{}, err
	}
	runtime := Runtime{
		Listen:  listen,
		DataDir: layout.Root,
		TLSCert: firstNonEmpty(overrides.TLSCert, os.Getenv("ARCA_TLS_CERT")),
		TLSKey:  firstNonEmpty(overrides.TLSKey, os.Getenv("ARCA_TLS_KEY")),
		Layout:  layout,
		File: FileConfig{
			InstanceName:           "Arca",
			FilesystemReserveBytes: 1 << 30,
		},
		secretEnv: make(map[string]bool),
	}
	if err := readJSON(layout.ConfigFile, &runtime.File); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Runtime{}, fmt.Errorf("read config: %w", err)
	} else if err == nil {
		runtime.FromDisk = true
	}
	if err := readJSON(layout.SecretsFile, &runtime.Secrets); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Runtime{}, fmt.Errorf("read secrets: %w", err)
	}

	runtime.File.PublicURL = firstNonEmpty(os.Getenv("ARCA_PUBLIC_URL"), runtime.File.PublicURL)
	runtime.File.WorkOSClientID = firstNonEmpty(os.Getenv("ARCA_WORKOS_CLIENT_ID"), runtime.File.WorkOSClientID)
	for _, item := range []struct {
		name   string
		target *string
	}{
		{"ARCA_WORKOS_API_KEY", &runtime.Secrets.WorkOSAPIKey},
		{"ARCA_COOKIE_KEY", &runtime.Secrets.CookieKey},
		{"ARCA_CODE_HMAC_KEY", &runtime.Secrets.CodeHMACKey},
		{"ARCA_STATUS_HMAC_KEY", &runtime.Secrets.StatusHMACKey},
	} {
		if value := os.Getenv(item.name); value != "" {
			*item.target = value
			runtime.secretEnv[item.name] = true
		}
	}
	if value := os.Getenv("ARCA_FILESYSTEM_RESERVE_BYTES"); value != "" {
		var parsed int64
		if _, err := fmt.Sscan(value, &parsed); err != nil || parsed < 0 {
			return Runtime{}, fmt.Errorf("invalid ARCA_FILESYSTEM_RESERVE_BYTES")
		}
		runtime.File.FilesystemReserveBytes = parsed
	}
	return runtime, nil
}

func EnsureLayout(layout Layout) error {
	dirs := []string{layout.Root, layout.DatabaseDir, layout.BlobDir, layout.StagingDir, layout.PreviewDir, layout.LockDir}
	for _, dir := range dirs {
		if err := rejectSymlink(dir); err != nil {
			return err
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("secure %s: %w", dir, err)
		}
	}
	if err := sameDevice(layout.BlobDir, layout.StagingDir); err != nil {
		return err
	}
	return nil
}

func (r *Runtime) EnsureSecrets() error {
	for target, value := range map[string]*string{
		"cookie": &r.Secrets.CookieKey,
		"code":   &r.Secrets.CodeHMACKey,
		"status": &r.Secrets.StatusHMACKey,
	} {
		if *value != "" {
			if _, err := DecodeSecret(*value); err != nil {
				return fmt.Errorf("invalid %s secret: %w", target, err)
			}
			continue
		}
		generated, err := GenerateSecret(32)
		if err != nil {
			return err
		}
		*value = generated
	}
	return nil
}

func (r Runtime) Save() error {
	if err := EnsureLayout(r.Layout); err != nil {
		return err
	}
	if err := writeJSONAtomic(r.Layout.ConfigFile, r.File, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	persisted := r.Secrets
	if len(r.secretEnv) != 0 {
		var previous Secrets
		_ = readJSON(r.Layout.SecretsFile, &previous)
		if r.secretEnv["ARCA_WORKOS_API_KEY"] {
			persisted.WorkOSAPIKey = previous.WorkOSAPIKey
		}
		if r.secretEnv["ARCA_COOKIE_KEY"] {
			persisted.CookieKey = previous.CookieKey
		}
		if r.secretEnv["ARCA_CODE_HMAC_KEY"] {
			persisted.CodeHMACKey = previous.CodeHMACKey
		}
		if r.secretEnv["ARCA_STATUS_HMAC_KEY"] {
			persisted.StatusHMACKey = previous.StatusHMACKey
		}
	}
	if err := writeJSONAtomic(r.Layout.SecretsFile, persisted, 0o600); err != nil {
		return fmt.Errorf("write secrets: %w", err)
	}
	return nil
}

func (r Runtime) ValidateConfigured() error {
	if strings.TrimSpace(r.File.InstanceName) == "" {
		return errors.New("instance name is required")
	}
	if strings.TrimSpace(r.File.WorkOSClientID) == "" || strings.TrimSpace(r.Secrets.WorkOSAPIKey) == "" {
		return errors.New("WorkOS client ID and API key are required")
	}
	parsed, err := url.Parse(r.File.PublicURL)
	if err != nil || parsed.Host == "" {
		return errors.New("a valid public URL is required")
	}
	host := parsed.Hostname()
	if parsed.Scheme != "https" && !isLoopbackHost(host) {
		return errors.New("public URL must use HTTPS unless it is loopback")
	}
	if (r.TLSCert == "") != (r.TLSKey == "") {
		return errors.New("both TLS certificate and key are required")
	}
	return nil
}

func GenerateSecret(bytes int) (string, error) {
	buffer := make([]byte, bytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate random secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func DecodeSecret(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	if len(decoded) < 32 {
		return nil, errors.New("secret must contain at least 32 bytes")
	}
	return decoded, nil
}

type Lock struct {
	file *os.File
}

func AcquireLock(path string) (*Lock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open instance lock: %w", err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errors.New("another Arca process already owns this data directory")
		}
		return nil, fmt.Errorf("acquire instance lock: %w", err)
	}
	if err := file.Truncate(0); err == nil {
		_, _ = fmt.Fprintf(file, "%d\n", os.Getpid())
		_ = file.Sync()
	}
	return &Lock{file: file}, nil
}

func (l *Lock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	_ = unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	return l.file.Close()
}

func readJSON(path string, destination any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	return nil
}

func writeJSONAtomic(path string, value any, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	temporary, err := os.CreateTemp(dir, ".arca-config-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}
	if err := temporary.Chmod(mode); err != nil {
		cleanup()
		return err
	}
	encoder := json.NewEncoder(temporary)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		cleanup()
		return err
	}
	if err := temporary.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		_ = os.Remove(temporaryPath)
		return err
	}
	directory, err := os.Open(dir)
	if err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

func rejectSymlink(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("data path %s must not be a symlink", path)
	}
	return nil
}

func sameDevice(first, second string) error {
	firstInfo, err := os.Stat(first)
	if err != nil {
		return err
	}
	secondInfo, err := os.Stat(second)
	if err != nil {
		return err
	}
	firstStat, firstOK := firstInfo.Sys().(*syscall.Stat_t)
	secondStat, secondOK := secondInfo.Sys().(*syscall.Stat_t)
	if firstOK && secondOK && firstStat.Dev != secondStat.Dev {
		return errors.New("blob and staging directories must be on the same filesystem")
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
