package crypto

// This file exports internal functions for testing purposes only.

// DecodeMasterKeyForTest exports decodeMasterKey for testing.
func DecodeMasterKeyForTest(keyStr string) ([]byte, error) {
	return decodeMasterKey(keyStr)
}

// LoadMasterKeyFromFileForTest exports loadMasterKeyFromFile for testing.
func LoadMasterKeyFromFileForTest(filename string) ([]byte, error) {
	return loadMasterKeyFromFile(filename)
}
