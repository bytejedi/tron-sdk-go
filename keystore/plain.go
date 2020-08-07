package keystore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type keyStorePlain struct {
	keysDirPath string
}

func (ks keyStorePlain) GetKey(addr Address, filename, auth string) (*Key, error) {
	fd, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	key := new(Key)
	if err := json.NewDecoder(fd).Decode(key); err != nil {
		return nil, err
	}
	if !bytes.Equal(key.Address, addr) {
		return nil, fmt.Errorf("key content mismatch: have address %x, want %x", key.Address, addr)
	}
	return key, nil
}

func (ks keyStorePlain) StoreKey(filename string, key *Key, auth string) error {
	content, err := json.Marshal(key)
	if err != nil {
		return err
	}
	return writeKeyFile(filename, content)
}

func (ks keyStorePlain) JoinPath(filename string) string {
	if filepath.IsAbs(filename) {
		return filename
	}
	return filepath.Join(ks.keysDirPath, filename)
}
