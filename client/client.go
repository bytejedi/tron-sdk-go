package client

import (
	"time"

	"github.com/bytejedi/tron-sdk-go/proto/api"

	"github.com/labstack/gommon/log"
	"google.golang.org/grpc"
)

const (
	// Don't wait for confirmation by default
	confirmationTimeout = 20

	// Grpc response timeout
	grpcTimeout = 5 * time.Second
)

var Conn *GrpcClient

func Init(address string) {
	Conn = NewGrpcClient(address)
	if err := Conn.Start(); err != nil {
		panic(err)
	}
	log.Infof("%s GRPC connected.", address)
}

// GrpcClient controller structure
type GrpcClient struct {
	Address string
	Conn    *grpc.ClientConn
	Client  api.WalletClient
}

// NewGrpcClient create grpc controller
func NewGrpcClient(address string) *GrpcClient {
	client := new(GrpcClient)
	client.Address = address
	return client
}

// Start initiate grpc  connection
func (g *GrpcClient) Start() error {
	var err error
	g.Conn, err = grpc.Dial(g.Address, grpc.WithInsecure())
	if err != nil {
		return err
	}
	g.Client = api.NewWalletClient(g.Conn)
	return nil
}

// Stop GRPC Connection
func (g *GrpcClient) Stop() {
	if g.Conn != nil {
		g.Conn.Close()
	}
}

// Reconnect GRPC
func (g *GrpcClient) Reconnect(url string) error {
	g.Stop()
	if len(url) > 0 {
		g.Address = url
	}
	g.Start()
	return nil
}
