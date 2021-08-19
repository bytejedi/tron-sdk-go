package keystore

import (
	"crypto/ecdsa"
	"math/big"

	"github.com/bytejedi/tron-sdk-go/utils"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	// HashLength is the expected length of the hash
	HashLength = 32
	// AddressLength is the expected length of the address
	AddressLength = 21
	// TronBytePrefix is the hex prefix to address
	TronBytePrefix = byte(0x41)
)

// Address represents the 21 byte address of an Tron account.
type Address []byte

// Bytes get bytes from address
func (a Address) Bytes() []byte {
	return a[:]
}

// Hex get bytes from address in string
func (a Address) Hex() string {
	return utils.ToHex(a[:])
}

// HexToAddress returns Address with byte values of s.
// If s is larger than len(h), s will be cropped from the left.
func HexToAddress(s string) (Address, error) {
	return utils.FromHex(s)
}

// Base58ToAddress returns Address with byte values of s.
func Base58ToAddress(s string) (Address, error) {
	addr, err := utils.DecodeCheck(s)
	if err != nil {
		return nil, err
	}
	return addr, nil
}

// String implements fmt.Stringer.
func (a Address) String() string {
	if a[0] == 0 {
		return new(big.Int).SetBytes(a.Bytes()).String()
	}
	return utils.EncodeCheck(a.Bytes())
}

// PubkeyToAddress returns address from ecdsa public key
func PubkeyToAddress(p ecdsa.PublicKey) Address {
	address := crypto.PubkeyToAddress(p)

	addressTron := make([]byte, 0)
	addressTron = append(addressTron, TronBytePrefix)
	addressTron = append(addressTron, address.Bytes()...)
	return addressTron
}
