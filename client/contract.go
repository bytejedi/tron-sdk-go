package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"strconv"

	"github.com/bytejedi/tron-sdk-go/keystore"
	"github.com/bytejedi/tron-sdk-go/proto/api"
	"github.com/bytejedi/tron-sdk-go/proto/core"
	"github.com/bytejedi/tron-sdk-go/proto/core/contract"
	"github.com/bytejedi/tron-sdk-go/utils"

	"github.com/golang/protobuf/proto"
)

// TriggerContract and return tx result
func (g *GrpcClient) TriggerContract(from, contractAddress, method, jsonString string,
	feeLimit, tAmount int64, tTokenID string, tTokenAmount int64) (*api.TransactionExtention, error) {
	fromDesc, err := keystore.Base58ToAddress(from)
	if err != nil {
		return nil, err
	}

	contractDesc, err := keystore.Base58ToAddress(contractAddress)
	if err != nil {
		return nil, err
	}

	param, err := LoadFromJSON(jsonString)
	if err != nil {
		return nil, err
	}

	dataBytes, err := Pack(method, param)
	if err != nil {
		return nil, err
	}

	ct := &contract.TriggerSmartContract{
		OwnerAddress:    fromDesc.Bytes(),
		ContractAddress: contractDesc.Bytes(),
		Data:            dataBytes,
	}
	if tAmount > 0 {
		ct.CallValue = tAmount
	}
	if len(tTokenID) > 0 && tTokenAmount > 0 {
		ct.CallTokenValue = tTokenAmount
		ct.TokenId, err = strconv.ParseInt(tTokenID, 10, 64)
		if err != nil {
			return nil, err
		}
	}

	return g.triggerContract(ct, feeLimit)
}

// triggerContract and return tx result
func (g *GrpcClient) triggerContract(ct *contract.TriggerSmartContract, feeLimit int64) (*api.TransactionExtention, error) {
	ctx, cancel := context.WithTimeout(context.Background(), grpcTimeout)
	defer cancel()

	tx, err := g.Client.TriggerContract(ctx, ct)
	if err != nil {
		return nil, err
	}

	if tx.Result.Code > 0 {
		return nil, fmt.Errorf("%s", string(tx.Result.Message))
	}
	if feeLimit > 0 {
		tx.Transaction.RawData.FeeLimit = feeLimit
		// update hash
		g.UpdateHash(tx)
	}
	return tx, err
}

// UpdateHash after local changes
func (g *GrpcClient) UpdateHash(tx *api.TransactionExtention) error {
	rawData, err := proto.Marshal(tx.Transaction.GetRawData())
	if err != nil {
		return err
	}

	h256h := sha256.New()
	h256h.Write(rawData)
	hash := h256h.Sum(nil)
	tx.Txid = hash
	return nil
}

// Broadcast broadcast TX
func (g *GrpcClient) Broadcast(tx *core.Transaction) (*api.Return, error) {
	ctx, cancel := context.WithTimeout(context.Background(), grpcTimeout)
	defer cancel()
	result, err := g.Client.BroadcastTransaction(ctx, tx)
	if err != nil {
		return nil, err
	}
	if !result.GetResult() {
		return nil, fmt.Errorf("result error: %s", result.GetMessage())
	}
	if result.GetCode() != api.Return_SUCCESS {
		return nil, fmt.Errorf("result error(%s): %s", result.GetCode(), result.GetMessage())
	}
	return result, nil
}

//GetTransactionInfoByID returns transaction receipt by ID
func (g *GrpcClient) GetTransactionInfoByID(id string) (*core.TransactionInfo, error) {
	transactionID := new(api.BytesMessage)
	var err error

	transactionID.Value, err = utils.FromHex(id)
	if err != nil {
		return nil, fmt.Errorf("get transaction by id error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), grpcTimeout)
	defer cancel()

	txi, err := g.Client.GetTransactionInfoById(ctx, transactionID)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(txi.Id, transactionID.Value) {
		return txi, nil
	}
	return nil, fmt.Errorf("transaction info not found")
}
