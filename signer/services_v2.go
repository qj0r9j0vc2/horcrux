package signer

import (
	"net"
	"time"

	cometlog "github.com/cometbft/cometbft/libs/log"
	cometservice "github.com/cometbft/cometbft/libs/service"
)

// StartRemoteSignersV2 starts remote signers with support for multiple protocol versions
func StartRemoteSignersV2(
	services []cometservice.Service,
	logger cometlog.Logger,
	privVal PrivValidator,
	nodes []string,
	maxReadSize int,
	protocolVersion ProtocolVersion,
) ([]cometservice.Service, error) {
	var err error
	go StartMetrics()
	
	// Log the protocol version being used
	logger.Info("Starting remote signers with protocol version", "version", protocolVersion)
	
	for _, node := range nodes {
		// CometBFT requires a connection within 3 seconds of start or crashes
		// A long timeout such as 30 seconds would cause the sentry to fail in loops
		// Use a short timeout and dial often to connect within 3 second window
		dialer := net.Dialer{Timeout: 2 * time.Second}
		
		var s cometservice.Service
		
		// For backward compatibility, we check if we should use the new V2 signer
		if protocolVersion == ProtocolVersionV1 {
			// Use V2 signer with v1 protocol
			signer, err := NewReconnRemoteSignerV2WithDialer(node, logger, privVal, dialer, maxReadSize, protocolVersion)
			if err != nil {
				return nil, err
			}
			s = signer
		} else {
			// Use original signer for legacy protocol (default behavior)
			s = NewReconnRemoteSigner(node, logger, privVal, dialer, maxReadSize)
		}

		err = s.Start()
		if err != nil {
			return nil, err
		}

		services = append(services, s)
	}
	return services, err
}