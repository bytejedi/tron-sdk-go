package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/bytejedi/tron-sdk-go/abi"
	"github.com/bytejedi/tron-sdk-go/keystore"
	"github.com/bytejedi/tron-sdk-go/utils"
	ethabi "github.com/ethereum/go-ethereum/accounts/abi"
	ethcmn "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/miguelmota/go-ethereum-hdwallet"
	"github.com/tyler-smith/go-bip39"
	"github.com/tyler-smith/go-bip39/wordlists"
)

func main() {
	keystorePassword := "password"

	// Set wordlist
	bip39.SetWordList(wordlists.English)
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		log.Fatal(err)
	}

	mnemonic, _ := bip39.NewMnemonic(entropy)
	seed := bip39.NewSeed(mnemonic, keystorePassword)

	wallet, err := hdwallet.NewFromSeed(seed)
	if err != nil {
		log.Fatal(err)
	}

	path := hdwallet.MustParseDerivationPath("m/44'/195'/0'/0/0")
	account, err := wallet.Derive(path, false)
	if err != nil {
		log.Fatal(err)
	}

	privKeyHex, err := wallet.PrivateKeyHex(account)
	if err != nil {
		log.Fatal(err)
	}

	pubKeyHex, err := wallet.PublicKeyHex(account)
	if err != nil {
		log.Fatal(err)
	}

	privateKeyECDSA, err := wallet.PrivateKey(account)
	if err != nil {
		log.Fatal(err)
	}
	publicKeyECDSA, err := wallet.PublicKey(account)
	if err != nil {
		log.Fatal(err)
	}

	keystoreKey := keystore.NewKeyFromECDSA(privateKeyECDSA)
	keyjson, err := keystore.EncryptKey(keystoreKey, keystorePassword, keystore.StandardScryptN, keystore.StandardScryptP)
	if err != nil {
		log.Fatal(err)
	}

	tronAddress := keystore.PubkeyToAddress(*publicKeyECDSA)

	fmt.Println("mnemonic:", mnemonic)
	fmt.Println("base58 address:", tronAddress.String())
	fmt.Println("hex address:", hex.EncodeToString(tronAddress))
	fmt.Println("private key:", privKeyHex)
	fmt.Println("public key:", pubKeyHex)
	fmt.Println("keystore:", string(keyjson))

	abiJson, err := ioutil.ReadFile("./abi.json")
	if err != nil {
		log.Fatal(err)
	}

	a, err := ethabi.JSON(bytes.NewReader(abiJson))
	if err != nil {
		log.Fatal(err)
	}

	method := a.Methods["prepareMint"]
	paramJson := "[{\"uint256\":\"1212\"},{\"uint256[4]\":[\"2\",\"3\",\"4\",\"5\"]},{\"uint256[2]\":[\"39\",\"10\"]},{\"address\":\"TCQRkmYMbb8bzrZfrtcokox8hwVmY3DCVP\"},{\"address[4]\":[\"TCudRMFJDPChH2FNjVb82cvbREMPNUm1pj\",\"TCudRMFJDPChH2FNjVb82cvbREMPNUm1pj\",\"TCudRMFJDPChH2FNjVb82cvbREMPNUm1pj\",\"TCudRMFJDPChH2FNjVb82cvbREMPNUm1pj\"]},{\"uint256\":\"4\"}]"
	paddedParamBytes, err := abi.Pack(&method, paramJson)
	if err != nil {
		log.Fatal(err)
	}

	paddedParamHex := utils.Bytes2Hex(paddedParamBytes)
	fmt.Println("triggersmartcontract.parameter:", paddedParamHex)

	// sign
	txId := "966f7f2c4aa31eafcc48a8e21554bd2f7a5b517890ccaec78beea249358b429a"
	txHashBytes := ethcmn.Hex2Bytes(txId)

	key, err := keystore.DecryptKey(keyjson, keystorePassword)
	if err != nil {
		log.Fatal(err)
	}
	defer keystore.ZeroKey(key.PrivateKey)
	signature, err := crypto.Sign(txHashBytes, key.PrivateKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("sig from keystore:", utils.Bytes2Hex(signature))

	signature2, err := crypto.Sign(txHashBytes, privateKeyECDSA)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("sig from private key:", utils.Bytes2Hex(signature2))
}
