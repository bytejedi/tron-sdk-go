package keystore

import (
	"os"
)

var KS *KeyStore

// Init make keystore directory and initialize KS
func Init(p string) {
	if _, err := os.Stat(p); os.IsNotExist(err) {
		if err := os.MkdirAll(p, 0700); err != nil {
			panic(err)
		}
	}

	KS = NewKeyStore(p, StandardScryptN, StandardScryptP)
}
