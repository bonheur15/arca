//go:build linux

package database

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func validateLocalFilesystem(path string) error {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return fmt.Errorf("inspect database filesystem: %w", err)
	}
	networkFilesystems := map[int64]string{
		unix.NFS_SUPER_MAGIC:   "NFS",
		unix.CIFS_SUPER_MAGIC:  "CIFS",
		unix.SMB2_SUPER_MAGIC:  "SMB2",
		unix.AFS_SUPER_MAGIC:   "AFS",
		unix.CODA_SUPER_MAGIC:  "Coda",
		unix.CEPH_SUPER_MAGIC:  "CephFS",
		unix.V9FS_MAGIC:        "9P",
		unix.OCFS2_SUPER_MAGIC: "OCFS2",
	}
	if name, found := networkFilesystems[int64(stat.Type)]; found {
		return fmt.Errorf("SQLite WAL database cannot run on shared filesystem %s", name)
	}
	return nil
}
