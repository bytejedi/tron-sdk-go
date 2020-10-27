package abi

import (
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strconv"
	"strings"

	"github.com/bytejedi/tron-sdk-go/keystore"

	ethabi "github.com/ethereum/go-ethereum/accounts/abi"
	ethcmn "github.com/ethereum/go-ethereum/common"
	"golang.org/x/crypto/sha3"
)

// Param list
type Param map[string]interface{}

// loadFromJSON string into ABI data
func loadFromJSON(jString string) ([]Param, error) {
	if len(jString) == 0 {
		return nil, nil
	}
	data := []Param{}
	err := json.Unmarshal([]byte(jString), &data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// Signature of a method
func Signature(method string) []byte {
	// hash method
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write([]byte(method))
	b := hasher.Sum(nil)
	return b[:4]
}

func convetToAddress(v interface{}) (ethcmn.Address, error) {
	switch v.(type) {
	case string:
		addr, err := keystore.Base58ToAddress(v.(string))
		if err != nil {
			return ethcmn.Address{}, fmt.Errorf("invalid address %s: %+v", v.(string), err)
		}
		return ethcmn.BytesToAddress(addr.Bytes()[len(addr.Bytes())-20:]), nil
	}
	return ethcmn.Address{}, fmt.Errorf("invalid address %v", v)
}

func convertToInt(ty ethabi.Type, v interface{}) interface{} {
	if ty.T == ethabi.IntTy && ty.Size <= 64 {
		tmp, _ := strconv.ParseInt(v.(string), 10, ty.Size)
		switch ty.Size {
		case 8:
			v = int8(tmp)
		case 16:
			v = int16(tmp)
		case 32:
			v = int32(tmp)
		case 64:
			v = int64(tmp)
		}
	} else if ty.T == ethabi.UintTy && ty.Size <= 64 {
		tmp, _ := strconv.ParseUint(v.(string), 10, ty.Size)
		switch ty.Size {
		case 8:
			v = uint8(tmp)
		case 16:
			v = uint16(tmp)
		case 32:
			v = uint32(tmp)
		case 64:
			v = uint64(tmp)
		}
	} else {
		v, _ = new(big.Int).SetString(v.(string), 10)
	}
	return v
}

// GetPaddedParam return padded params bytes
func GetPaddedParam(method *ethabi.Method, param []Param) ([]byte, error) {
	values := make([]interface{}, 0)

	for _, p := range param {
		if len(p) != 1 {
			return nil, fmt.Errorf("invalid param %+v", p)
		}
		for k, v := range p {
			if k == "uint" {
				k = "uint256"
			} else if strings.HasPrefix(k, "uint[") {
				k = strings.Replace(k, "uint[", "uint256[", 1)
			}
			ty, err := ethabi.NewType(k, "", nil)
			if err != nil {
				return nil, fmt.Errorf("invalid param %+v: %+v", p, err)
			}

			if ty.T == ethabi.SliceTy || ty.T == ethabi.ArrayTy {
				if ty.Elem.T == ethabi.AddressTy {
					tmp := v.([]interface{})
					v = make([]ethcmn.Address, 0)
					for i := range tmp {
						addr, err := convetToAddress(tmp[i])
						if err != nil {
							return nil, err
						}
						v = append(v.([]ethcmn.Address), addr)
					}
				}

				if (ty.Elem.T == ethabi.IntTy || ty.Elem.T == ethabi.UintTy) && reflect.TypeOf(v).Elem().Kind() == reflect.Interface {
					if ty.Elem.Size > 64 {
						tmp := make([]*big.Int, 0)
						for _, i := range v.([]interface{}) {
							if s, ok := i.(string); ok {
								value, _ := new(big.Int).SetString(s, 10)
								tmp = append(tmp, value)
							} else {
								return nil, fmt.Errorf("abi: cannot use %T as type string as argument", i)
							}
						}
						v = tmp
					} else {
						tmpI := make([]interface{}, 0)
						for _, i := range v.([]interface{}) {
							if s, ok := i.(string); ok {
								value, err := strconv.ParseUint(s, 10, ty.Elem.Size)
								if err != nil {
									return nil, err
								}
								tmpI = append(tmpI, value)
							} else {
								return nil, fmt.Errorf("abi: cannot use %T as type string as argument", i)
							}
						}
						switch ty.Elem.Size {
						case 8:
							tmp := make([]uint8, len(tmpI))
							for i, sv := range tmpI {
								tmp[i] = uint8(sv.(uint64))
							}
							v = tmp
						case 16:
							tmp := make([]uint16, len(tmpI))
							for i, sv := range tmpI {
								tmp[i] = uint16(sv.(uint64))
							}
							v = tmp
						case 32:
							tmp := make([]uint32, len(tmpI))
							for i, sv := range tmpI {
								tmp[i] = uint32(sv.(uint64))
							}
							v = tmp
						case 64:
							tmp := make([]uint64, len(tmpI))
							for i, sv := range tmpI {
								tmp[i] = sv.(uint64)
							}
							v = tmp
						}
					}
				}
			}

			if ty.T == ethabi.AddressTy {
				if v, err = convetToAddress(v); err != nil {
					return nil, err
				}
			}

			if (ty.T == ethabi.IntTy || ty.T == ethabi.UintTy) && reflect.TypeOf(v).Kind() == reflect.String {
				v = convertToInt(ty, v)
			}

			values = append(values, v)
		}
	}

	// convert params to bytes
	return method.Inputs.PackValues(values)
}

// Pack data into bytes
func Pack(method *ethabi.Method, paramsJson string) ([]byte, error) {
	params, err := loadFromJSON(paramsJson)
	if err != nil {
		return nil, err
	}

	pBytes, err := GetPaddedParam(method, params)
	if err != nil {
		return nil, err
	}
	return append(method.ID, pBytes...), nil
}

// DecodeOutputs unpack outputs data
func DecodeOutputs(method *ethabi.Method, outputs []byte) (interface{}, error) {
	res, err := method.Outputs.UnpackValues(outputs)
	if err != nil {
		return string(outputs), nil
	}
	return res, nil
}
