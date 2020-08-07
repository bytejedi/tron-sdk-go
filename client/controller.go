package client

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/golang/protobuf/proto"

	"github.com/bytejedi/tron-sdk-go/keystore"
	"github.com/bytejedi/tron-sdk-go/proto/api"
	"github.com/bytejedi/tron-sdk-go/proto/core"
	"github.com/bytejedi/tron-sdk-go/utils"
)

type sender struct {
	ks      *keystore.KeyStore
	account *keystore.Account
}

// Controller drives the transaction signing process
type Controller struct {
	executionError error
	resultError    error
	client         *GrpcClient
	tx             *core.Transaction
	sender         sender
	Behavior       behavior
	Result         *api.Return
	Receipt        *core.TransactionInfo
}

type behavior struct {
	DryRun               bool
	SigningImpl          SignerImpl
	ConfirmationWaitTime uint32
}

// NewController initializes a Controller, caller can control behavior via options
func NewController(
	client *GrpcClient,
	senderKs *keystore.KeyStore,
	senderAcct *keystore.Account,
	tx *core.Transaction,
	options ...func(*Controller),
) *Controller {

	ctrlr := &Controller{
		executionError: nil,
		resultError:    nil,
		client:         client,
		sender: sender{
			ks:      senderKs,
			account: senderAcct,
		},
		tx:       tx,
		Behavior: behavior{false, Software, 0},
	}
	for _, option := range options {
		option(ctrlr)
	}
	return ctrlr
}

func (c *Controller) signTxForSending() {
	if c.executionError != nil {
		return
	}
	signedTransaction, err := c.sender.ks.SignTx(*c.sender.account, c.tx)
	if err != nil {
		c.executionError = err
		return
	}
	c.tx = signedTransaction
}

// TransactionHash extract hash from TX
func (c *Controller) TransactionHash() (string, error) {
	rawData, err := c.GetRawData()
	if err != nil {
		return "", err
	}
	h256h := sha256.New()
	h256h.Write(rawData)
	hash := h256h.Sum(nil)
	return utils.ToHex(hash), nil
}

func (c *Controller) txConfirmation() {
	if c.executionError != nil || c.Behavior.DryRun {
		return
	}
	if c.Behavior.ConfirmationWaitTime > 0 {
		txHash, err := c.TransactionHash()
		if err != nil {
			c.executionError = fmt.Errorf("could not get tx hash")
			return
		}
		//fmt.Printf("TX hash: %s\nWaiting for confirmation....", txHash)
		start := int(c.Behavior.ConfirmationWaitTime)
		for {
			// GETTX by ID
			if txi, err := c.client.GetTransactionInfoByID(txHash); err == nil {
				// check receipt
				if txi.Result != 0 {
					c.resultError = fmt.Errorf("%s", txi.ResMessage)
				}
				// Add receipt
				c.Receipt = txi
				return
			}
			if start < 0 {
				c.executionError = fmt.Errorf("could not confirm transaction after %d seconds", c.Behavior.ConfirmationWaitTime)
				return
			}
			time.Sleep(time.Second)
			start--
		}
	} else {
		c.Receipt = &core.TransactionInfo{}
		c.Receipt.Receipt = &core.ResourceReceipt{}
	}

}

// GetResultError return result error
func (c *Controller) GetResultError() error {
	return c.resultError
}

// ExecuteTransaction is the single entrypoint to execute a plain transaction.
// Each step in transaction creation, execution probably includes a mutation
// Each becomes a no-op if executionError occurred in any previous step
func (c *Controller) ExecuteTransaction() error {
	switch c.Behavior.SigningImpl {
	case Software:
		c.signTxForSending()
	}
	c.sendSignedTx()
	c.txConfirmation()
	return c.executionError
}

// GetRawData Byes from Transaction
func (c *Controller) GetRawData() ([]byte, error) {
	return proto.Marshal(c.tx.GetRawData())
}

func (c *Controller) sendSignedTx() {
	if c.executionError != nil || c.Behavior.DryRun {
		return
	}
	result, err := c.client.Broadcast(c.tx)
	if err != nil {
		c.executionError = err
		return
	}
	if result.Code != 0 {
		c.executionError = fmt.Errorf("bad transaction: %v", string(result.GetMessage()))
	}
	c.Result = result
}

func ControllerBehavior(ctlr *Controller) {
	ctlr.Behavior.ConfirmationWaitTime = confirmationTimeout
}
