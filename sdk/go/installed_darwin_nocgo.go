//go:build darwin && !cgo

package orbit

const installedDataName = "orbit-storage.bin"

func openInstalledFiles(string, []byte) (installedFiles, string, bool, error) {
	return nil, "", false, ErrNativeSupportRequired
}
