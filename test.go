package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/bytejedi/tron-sdk-go/abi"
	"github.com/bytejedi/tron-sdk-go/keystore"
	"github.com/bytejedi/tron-sdk-go/utils"

	ethcmn "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/miguelmota/go-ethereum-hdwallet"
	"github.com/tyler-smith/go-bip39"
	"github.com/tyler-smith/go-bip39/wordlists"
)

func main() {
	keystorePassword := "password"

	// Set wordlist
	bip39.SetWordList(wordlists.ChineseSimplified)
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

	fmt.Println("助记词:", mnemonic)
	fmt.Println("base58地址:", tronAddress.String())
	fmt.Println("hex地址:", hex.EncodeToString(tronAddress))
	fmt.Println("私钥:", privKeyHex)
	fmt.Println("公钥:", pubKeyHex)
	fmt.Println("keystore:", string(keyjson))

	paramStr := "[{\"address\":\"TRu2DruRJDjVsqno7CwXMzJb7vQTpVaKmL\"},{\"address\":\"TRu2DruRJDjVsqno7CwXMzJb7vQTpVaKmL\"},{\"uint256\":\"10000\"},{\"uint256\":\"0\"}]"
	param, err := abi.LoadFromJSON(paramStr)
	if err != nil {
		log.Fatal(err)
	}

	paddedParamBytes, err := abi.GetPaddedParam(param)
	if err != nil {
		log.Fatal(err)
	}

	paddedParamHex := utils.Bytes2Hex(paddedParamBytes)
	fmt.Println("triggersmartcontract接口parameter入参:", paddedParamHex)

	// sign
	txId := "966f7f2c4aa31eafcc48a8e21554bd2f7a5b517890ccaec78beea249358b429a"
	txHashBytes := ethcmn.Hex2Bytes(txId)

	key, err := keystore.DecryptKey(keyjson, keystorePassword)
	if err != nil {
		log.Fatal(err)
	}
	// 抹掉runtime内存中的私钥
	defer keystore.ZeroKey(key.PrivateKey)
	signature, err := crypto.Sign(txHashBytes, key.PrivateKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("使用keystore签名tx的签名值:", utils.Bytes2Hex(signature))

	signature2, err := crypto.Sign(txHashBytes, privateKeyECDSA)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("使用私钥签名tx的签名值:", utils.Bytes2Hex(signature2))
}
