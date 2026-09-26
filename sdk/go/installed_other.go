//go:build !linux && !windows

package orbit

func openInstalledFiles(string, []byte) (installedFiles, string, bool, error) {
	return nil, "", false, ErrStorage
}
