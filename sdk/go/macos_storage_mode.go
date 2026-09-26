package orbit

func macDirectoryModeAllowed(owner, effectiveUID, mode uint32, leaf bool) bool {
	mode &= 07777
	if leaf {
		return owner == effectiveUID && mode&0077 == 0
	}
	ownerOK := owner == 0 || owner == effectiveUID
	return ownerOK && (mode&0022 == 0 || owner == 0 && mode&01000 != 0)
}
