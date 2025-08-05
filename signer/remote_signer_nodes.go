package signer

import (
	"net"
	"time"
	
	"github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/libs/service"
)

// StartRemoteSignersWithNodes starts remote signers with per-node protocol version support
func StartRemoteSignersWithNodes(
	services []service.Service,
	logger log.Logger,
	privVal PrivValidator,
	nodes ChainNodes,
	maxReadSize int,
) ([]service.Service, error) {
	nodeServices := make([]service.Service, 0, len(nodes))
	
	for _, node := range nodes {
		protocolVersion := node.GetProtocolVersion()
		
		logger.Info("Starting remote signer", 
			"address", node.PrivValAddr, 
			"protocol", protocolVersion)
		
		var s service.Service
		var err error
		
		switch protocolVersion {
		case ProtocolVersionV1:
			// Use V2 remote signer for CometBFT v1.0 support
			s, err = NewReconnRemoteSignerV2(node.PrivValAddr, logger, privVal, maxReadSize, protocolVersion)
		default:
			// Use legacy remote signer for backward compatibility
			dialer := net.Dialer{Timeout: 2 * time.Second}
			s = NewReconnRemoteSigner(node.PrivValAddr, logger, privVal, dialer, maxReadSize)
		}
		
		if err != nil {
			return nil, err
		}
		
		if err := s.Start(); err != nil {
			return nil, err
		}
		
		nodeServices = append(nodeServices, s)
	}
	
	return append(services, nodeServices...), nil
}

