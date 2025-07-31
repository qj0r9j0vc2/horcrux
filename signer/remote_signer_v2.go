package signer

import (
	"context"
	"fmt"
	"net"
	"time"

	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cometlog "github.com/cometbft/cometbft/libs/log"
	cometnet "github.com/cometbft/cometbft/libs/net"
	cometservice "github.com/cometbft/cometbft/libs/service"
	cometp2pconn "github.com/cometbft/cometbft/p2p/conn"
	cometprotoprivval "github.com/cometbft/cometbft/proto/tendermint/privval"
	cometbftprivvalv1 "github.com/cometbft/cometbft/api/cometbft/privval/v1"
)

// ReconnRemoteSignerV2 dials using its dialer and responds to any
// signature requests using its privVal. It supports both legacy and v1 protocols.
type ReconnRemoteSignerV2 struct {
	cometservice.BaseService

	address         string
	privKey         cometcryptoed25519.PrivKey
	privVal         PrivValidator
	dialer          net.Dialer
	maxReadSize     int
	protocolVersion ProtocolVersion
	protocol        PrivValProtocol
}

// NewReconnRemoteSignerV2 return a ReconnRemoteSignerV2 that will dial using the given
// dialer and respond to any signature requests over the connection
// using the given privVal.
//
// If the connection is broken, the ReconnRemoteSignerV2 will attempt to reconnect.
func NewReconnRemoteSignerV2(
	address string,
	logger cometlog.Logger,
	privVal PrivValidator,
	dialer net.Dialer,
	maxReadSize int,
	protocolVersion ProtocolVersion,
) (*ReconnRemoteSignerV2, error) {
	protocol, err := NewPrivValProtocol(protocolVersion)
	if err != nil {
		return nil, err
	}

	rs := &ReconnRemoteSignerV2{
		address:         address,
		privVal:         privVal,
		dialer:          dialer,
		privKey:         cometcryptoed25519.GenPrivKey(),
		maxReadSize:     maxReadSize,
		protocolVersion: protocolVersion,
		protocol:        protocol,
	}

	rs.BaseService = *cometservice.NewBaseService(logger, "RemoteSignerV2", rs)
	return rs, nil
}

// OnStart implements cmn.Service.
func (rs *ReconnRemoteSignerV2) OnStart() error {
	go rs.loop(context.Background())
	return nil
}

// OnStop implements cmn.Service.
func (rs *ReconnRemoteSignerV2) OnStop() {
	rs.privVal.Stop()
}

func (rs *ReconnRemoteSignerV2) establishConnection(ctx context.Context) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, connRetrySec*time.Second)
	defer cancel()

	proto, address := cometnet.ProtocolAndAddress(rs.address)
	netConn, err := rs.dialer.DialContext(ctx, proto, address)
	if err != nil {
		return nil, fmt.Errorf("dial error: %w", err)
	}

	conn, err := cometp2pconn.MakeSecretConnection(netConn, rs.privKey)
	if err != nil {
		netConn.Close()
		return nil, fmt.Errorf("secret connection error: %w", err)
	}

	return conn, nil
}

// main loop for ReconnRemoteSignerV2
func (rs *ReconnRemoteSignerV2) loop(ctx context.Context) {
	var conn net.Conn
	for {
		if !rs.IsRunning() {
			rs.closeConn(conn)
			return
		}

		retries := 0
		for conn == nil {
			var err error
			timer := time.NewTimer(connRetrySec * time.Second)
			conn, err = rs.establishConnection(ctx)
			if err == nil {
				sentryConnectTries.WithLabelValues(rs.address).Set(0)
				timer.Stop()
				rs.Logger.Info("Connected to Sentry", "address", rs.address, "protocol", rs.protocolVersion)
				break
			}

			sentryConnectTries.WithLabelValues(rs.address).Add(1)
			totalSentryConnectTries.WithLabelValues(rs.address).Inc()
			retries++
			rs.Logger.Error(
				"Error establishing connection, will retry",
				"sleep (s)", connRetrySec,
				"address", rs.address,
				"attempt", retries,
				"err", err,
			)
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				continue
			}
		}

		// since dialing can take time, we check running again
		if !rs.IsRunning() {
			rs.closeConn(conn)
			return
		}

		req, err := rs.protocol.ReadMessage(conn, rs.maxReadSize)
		if err != nil {
			rs.Logger.Error(
				"Failed to read message from connection",
				"address", rs.address,
				"err", err,
			)
			rs.closeConn(conn)
			conn = nil
			continue
		}

		// Get chain ID for the request (this is protocol-specific)
		chainID := rs.extractChainID(req)

		// handleRequest handles request errors. We always send back a response
		res, err := rs.protocol.HandleRequest(ctx, req, rs.privVal, chainID, rs.address, rs.Logger)
		if err != nil {
			rs.Logger.Error(
				"Failed to handle request",
				"address", rs.address,
				"err", err,
			)
			rs.closeConn(conn)
			conn = nil
			continue
		}

		err = rs.protocol.WriteMessage(conn, res)
		if err != nil {
			rs.Logger.Error(
				"Failed to write message to connection",
				"address", rs.address,
				"err", err,
			)
			rs.closeConn(conn)
			conn = nil
		}
	}
}

func (rs *ReconnRemoteSignerV2) closeConn(conn net.Conn) {
	if conn == nil {
		return
	}
	if err := conn.Close(); err != nil {
		rs.Logger.Error("Failed to close connection to chain node",
			"address", rs.address,
			"err", err,
		)
	}
}

// extractChainID extracts the chain ID from the request based on protocol version
func (rs *ReconnRemoteSignerV2) extractChainID(req interface{}) string {
	switch rs.protocolVersion {
	case ProtocolVersionLegacy:
		if msg, ok := req.(cometprotoprivval.Message); ok {
			switch typedReq := msg.Sum.(type) {
			case *cometprotoprivval.Message_SignVoteRequest:
				return typedReq.SignVoteRequest.ChainId
			case *cometprotoprivval.Message_SignProposalRequest:
				return typedReq.SignProposalRequest.ChainId
			case *cometprotoprivval.Message_PubKeyRequest:
				return typedReq.PubKeyRequest.ChainId
			}
		}
	case ProtocolVersionV1:
		if msg, ok := req.(*cometbftprivvalv1.Message); ok {
			switch typedReq := msg.Sum.(type) {
			case *cometbftprivvalv1.Message_SignVoteRequest:
				return typedReq.SignVoteRequest.ChainId
			case *cometbftprivvalv1.Message_SignProposalRequest:
				return typedReq.SignProposalRequest.ChainId
			case *cometbftprivvalv1.Message_PubKeyRequest:
				return typedReq.PubKeyRequest.ChainId
			}
		}
	}
	return ""
}