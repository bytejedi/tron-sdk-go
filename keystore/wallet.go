package keystore

import (
	"bytes"

	"github.com/ethereum/go-ethereum/crypto"
)

// keystoreWallet implements the Wallet interface for the original
// keystore.
type keystoreWallet struct {
	account  Account   // Single account contained in this wallet
	keystore *KeyStore // Keystore where the account originates from
}

// URL implements Wallet, returning the URL of the account within.
func (w *keystoreWallet) URL() URL {
	return w.account.URL
}

// Status implements Wallet, returning whether the account held by the
// keystore wallet is unlocked or not.
func (w *keystoreWallet) Status() (string, error) {
	w.keystore.mu.RLock()
	defer w.keystore.mu.RUnlock()

	if _, ok := w.keystore.unlocked[w.account.Address.String()]; ok {
		return "Unlocked", nil
	}
	return "Locked", nil
}

// Open implements Wallet, but is a noop for plain wallets since there
// is no connection or decryption step necessary to access the list of account.
func (w *keystoreWallet) Open(passphrase string) error { return nil }

// Close implements Wallet, but is a noop for plain wallets since there
// is no meaningful open operation.
func (w *keystoreWallet) Close() error { return nil }

// Accounts implements Wallet, returning an account list consisting of
// a single account that the plain kestore wallet contains.
func (w *keystoreWallet) Accounts() []Account {
	return []Account{w.account}
}

// Contains implements Wallet, returning whether a particular account is
// or is not wrapped by this wallet instance.
func (w *keystoreWallet) Contains(account Account) bool {
	return bytes.Equal(account.Address, w.account.Address) && (account.URL == (URL{}) || account.URL == w.account.URL)
}

// Derive implements Wallet, but is a noop for plain wallets since there
// is no notion of hierarchical account derivation for plain keystore account.
func (w *keystoreWallet) Derive(path DerivationPath, pin bool) (Account, error) {
	return Account{}, ErrNotSupported
}

// signHash attempts to sign the given hash with
// the given account. If the wallet does not wrap this particular account, an
// error is returned to avoid account leakage (even though in theory we may be
// able to sign via our shared keystore backend).
func (w *keystoreWallet) signHash(acc Account, hash []byte) ([]byte, error) {
	// Make sure the requested account is contained within
	if !w.Contains(acc) {
		return nil, ErrUnknownAccount
	}
	// Account seems valid, request the keystore to sign
	return w.keystore.SignHash(acc, hash)
}

// SignData signs keccak256(data). The mimetype parameter describes the type of data being signed
func (w *keystoreWallet) SignData(acc Account, mimeType string, data []byte) ([]byte, error) {
	return w.signHash(acc, crypto.Keccak256(data))
}

// SignDataWithPassphrase signs keccak256(data). The mimetype parameter describes the type of data being signed
func (w *keystoreWallet) SignDataWithPassphrase(acc Account, passphrase, mimeType string, data []byte) ([]byte, error) {
	// Make sure the requested account is contained within
	if !w.Contains(acc) {
		return nil, ErrUnknownAccount
	}
	// Account seems valid, request the keystore to sign
	return w.keystore.SignHashWithPassphrase(acc, passphrase, crypto.Keccak256(data))
}

func (w *keystoreWallet) SignText(acc Account, text []byte) ([]byte, error) {
	return w.signHash(acc, TextHash(text))
}

// SignTxWithPassphrase implements Wallet, attempting to sign the given
// transaction with the given account using passphrase as extra authentication.
func (w *keystoreWallet) SignTxWithPassphrase(acc Account, passphrase, rawData, txHash string) ([]byte, error) {
	// Make sure the requested account is contained within
	if !w.Contains(acc) {
		return nil, ErrUnknownAccount
	}
	// Account seems valid, request the keystore to sign
	return w.keystore.SignTxWithPassphrase(acc, passphrase, rawData, txHash)
}
