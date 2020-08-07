package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/url"
	"sort"

	"github.com/google/uuid"
)

// HmacSign sign the request data
func HmacSign(mapParams map[string]string, method, hostname, path, secretKey string) string {
	mapCloned := make(map[string]string)
	for key, value := range mapParams {
		mapCloned[key] = url.QueryEscape(value)
	}

	strParams := Map2UrlQueryBySort(mapCloned)

	strPayload := method + "\n" + hostname + "\n" + path + "\n" + strParams
	return ComputeHmac256(strPayload, secretKey)
}

// Map2UrlQueryBySort format map params to a string
func Map2UrlQueryBySort(mapParams map[string]string) string {
	var keys []string
	for key := range mapParams {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var strParams string
	for _, key := range keys {
		strParams += key + "=" + mapParams[key] + "&"
	}

	// remove "&" at the end of line
	if len(strParams) > 0 {
		strParams = string([]rune(strParams)[:len(strParams)-1])
	}

	return strParams
}

// ComputeHmac256 compute HMAC SHA256
func ComputeHmac256(strMessage string, strSecret string) string {
	key := []byte(strSecret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(strMessage))

	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func GenerateAccessKey() string {
	return base64.StdEncoding.EncodeToString([]byte(uuid.New().String()))
}

func GenerateSecretKey() string {
	return base64.StdEncoding.EncodeToString([]byte(uuid.New().String() + GenerateIDString()))
}

func Encrypter(plaintext string, aesSecretKey []byte) (ciphertext string, err error) {
	plainbytes, err := base64.StdEncoding.DecodeString(plaintext)
	if err != nil {
		return ciphertext, err
	}

	block, err := aes.NewCipher(aesSecretKey)
	if err != nil {
		return ciphertext, err
	}

	cipherbytes := make([]byte, aes.BlockSize+len(plainbytes))
	iv := cipherbytes[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return ciphertext, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherbytes[aes.BlockSize:], plainbytes)

	return base64.StdEncoding.EncodeToString(cipherbytes), nil
}

func Decrypter(ciphertext string, aesSecretKey []byte) (plaintext string, err error) {
	cipherbytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return plaintext, err
	}

	block, err := aes.NewCipher(aesSecretKey)
	if err != nil {
		return plaintext, err
	}

	if len(cipherbytes) < aes.BlockSize {
		return plaintext, errors.New("ciphertext too short")
	}
	iv := cipherbytes[:aes.BlockSize]
	cipherbytes = cipherbytes[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherbytes, cipherbytes)

	return base64.StdEncoding.EncodeToString(cipherbytes), nil
}
