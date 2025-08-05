package signer

import (
	"context"
	"errors"
	"fmt"
	"io"

	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cometcryptoencoding "github.com/cometbft/cometbft/crypto/encoding"
	cometlog "github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/libs/protoio"
	cometprotocrypto "github.com/cometbft/cometbft/proto/tendermint/crypto"
	cometprotoprivval "github.com/cometbft/cometbft/proto/tendermint/privval"
	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"

	// CometBFT v1.0 API imports
	cometbftprivvalv1 "github.com/cometbft/cometbft/api/cometbft/privval/v1"
	cometbfttypesv1 "github.com/cometbft/cometbft/api/cometbft/types/v1"
)

// ProtocolVersion represents the privval protocol version
type ProtocolVersion string

const (
	// ProtocolVersionLegacy represents the v0.38 and earlier protocol
	ProtocolVersionLegacy ProtocolVersion = "legacy"
	// ProtocolVersionV1 represents the v1.0 protocol
	ProtocolVersionV1 ProtocolVersion = "v1"
)

// PrivValProtocol defines the interface for handling different protocol versions
type PrivValProtocol interface {
	// ReadMessage reads a message from the connection
	ReadMessage(reader io.Reader, maxReadSize int) (interface{}, error)
	// WriteMessage writes a message to the connection
	WriteMessage(writer io.Writer, msg interface{}) error
	// HandleRequest processes a request and returns a response
	HandleRequest(ctx context.Context, req interface{}, privVal PrivValidator, chainID, address string, logger cometlog.Logger) (interface{}, error)
}

// LegacyProtocol implements the v0.38 protocol
type LegacyProtocol struct{}

// ReadMessage reads a v0.38 message
func (p *LegacyProtocol) ReadMessage(reader io.Reader, maxReadSize int) (interface{}, error) {
	if maxReadSize <= 0 {
		maxReadSize = 1024 * 1024 // 1MB
	}
	var msg cometprotoprivval.Message
	protoReader := protoio.NewDelimitedReader(reader, maxReadSize)
	_, err := protoReader.ReadMsg(&msg)
	return msg, err
}

// WriteMessage writes a v0.38 message
func (p *LegacyProtocol) WriteMessage(writer io.Writer, msg interface{}) error {
	message, ok := msg.(cometprotoprivval.Message)
	if !ok {
		return errors.New("invalid message type for legacy protocol")
	}
	protoWriter := protoio.NewDelimitedWriter(writer)
	_, err := protoWriter.WriteMsg(&message)
	return err
}

// HandleRequest handles a v0.38 request
func (p *LegacyProtocol) HandleRequest(ctx context.Context, req interface{}, privVal PrivValidator, chainID, address string, logger cometlog.Logger) (interface{}, error) {
	message, ok := req.(cometprotoprivval.Message)
	if !ok {
		return nil, errors.New("invalid request type for legacy protocol")
	}

	switch typedReq := message.Sum.(type) {
	case *cometprotoprivval.Message_SignVoteRequest:
		return p.handleSignVoteRequest(ctx, chainID, typedReq.SignVoteRequest.Vote, privVal, logger, address)
	case *cometprotoprivval.Message_SignProposalRequest:
		return p.handleSignProposalRequest(ctx, chainID, typedReq.SignProposalRequest.Proposal, privVal, logger, address)
	case *cometprotoprivval.Message_PubKeyRequest:
		return p.handlePubKeyRequest(ctx, chainID, privVal, logger, address)
	case *cometprotoprivval.Message_PingRequest:
		return p.handlePingRequest()
	default:
		logger.Error("Unknown request", "err", fmt.Errorf("%v", typedReq))
		return cometprotoprivval.Message{}, nil
	}
}

func (p *LegacyProtocol) handleSignVoteRequest(ctx context.Context, chainID string, vote *cometproto.Vote, privVal PrivValidator, logger cometlog.Logger, address string) (cometprotoprivval.Message, error) {
	msgSum := &cometprotoprivval.Message_SignedVoteResponse{SignedVoteResponse: &cometprotoprivval.SignedVoteResponse{
		Vote:  cometproto.Vote{},
		Error: nil,
	}}

	sig, voteExtSig, timestamp, err := SignAndTrack(
		ctx,
		logger,
		privVal,
		chainID,
		VoteToBlock(chainID, vote),
	)
	if err != nil {
		msgSum.SignedVoteResponse.Error = getRemoteSignerErrorLegacy(err)
		return cometprotoprivval.Message{Sum: msgSum}, nil
	}

	msgSum.SignedVoteResponse.Vote.Timestamp = timestamp
	msgSum.SignedVoteResponse.Vote.Signature = sig
	
	// CRITICAL: Vote extensions are only allowed for non-nil precommits
	// Same logic as V1 protocol to ensure consistency
	isPrecommit := vote.Type == cometproto.PrecommitType
	isNonNilBlock := len(vote.BlockID.Hash) > 0
	
	if len(voteExtSig) > 0 && isPrecommit && isNonNilBlock {
		msgSum.SignedVoteResponse.Vote.ExtensionSignature = voteExtSig
	}
	return cometprotoprivval.Message{Sum: msgSum}, nil
}

func (p *LegacyProtocol) handleSignProposalRequest(ctx context.Context, chainID string, proposal *cometproto.Proposal, privVal PrivValidator, logger cometlog.Logger, address string) (cometprotoprivval.Message, error) {
	msgSum := &cometprotoprivval.Message_SignedProposalResponse{
		SignedProposalResponse: &cometprotoprivval.SignedProposalResponse{
			Proposal: cometproto.Proposal{},
			Error:    nil,
		},
	}

	signature, _, timestamp, err := SignAndTrack(
		ctx,
		logger,
		privVal,
		chainID,
		ProposalToBlock(chainID, proposal),
	)
	if err != nil {
		msgSum.SignedProposalResponse.Error = getRemoteSignerErrorLegacy(err)
		return cometprotoprivval.Message{Sum: msgSum}, nil
	}

	msgSum.SignedProposalResponse.Proposal.Timestamp = timestamp
	msgSum.SignedProposalResponse.Proposal.Signature = signature
	return cometprotoprivval.Message{Sum: msgSum}, nil
}

func (p *LegacyProtocol) handlePubKeyRequest(ctx context.Context, chainID string, privVal PrivValidator, logger cometlog.Logger, address string) (cometprotoprivval.Message, error) {
	totalPubKeyRequests.WithLabelValues(chainID).Inc()
	msgSum := &cometprotoprivval.Message_PubKeyResponse{PubKeyResponse: &cometprotoprivval.PubKeyResponse{
		PubKey: cometprotocrypto.PublicKey{},
		Error:  nil,
	}}

	pubKey, err := privVal.GetPubKey(ctx, chainID)
	if err != nil {
		logger.Error(
			"Failed to get Pub Key",
			"chain_id", chainID,
			"node", address,
			"error", err,
		)
		msgSum.PubKeyResponse.Error = getRemoteSignerErrorLegacy(err)
		return cometprotoprivval.Message{Sum: msgSum}, nil
	}
	pk, err := cometcryptoencoding.PubKeyToProto(cometcryptoed25519.PubKey(pubKey))
	if err != nil {
		logger.Error(
			"Failed to encode Pub Key",
			"chain_id", chainID,
			"node", address,
			"error", err,
		)
		msgSum.PubKeyResponse.Error = getRemoteSignerErrorLegacy(err)
		return cometprotoprivval.Message{Sum: msgSum}, nil
	}
	msgSum.PubKeyResponse.PubKey = pk
	return cometprotoprivval.Message{Sum: msgSum}, nil
}

func (p *LegacyProtocol) handlePingRequest() (cometprotoprivval.Message, error) {
	return cometprotoprivval.Message{
		Sum: &cometprotoprivval.Message_PingResponse{
			PingResponse: &cometprotoprivval.PingResponse{},
		},
	}, nil
}

// V1Protocol implements the v1.0 protocol
type V1Protocol struct{}

// ReadMessage reads a v1.0 message
func (p *V1Protocol) ReadMessage(reader io.Reader, maxReadSize int) (interface{}, error) {
	if maxReadSize <= 0 {
		maxReadSize = 1024 * 1024 // 1MB
	}
	var msg cometbftprivvalv1.Message
	protoReader := protoio.NewDelimitedReader(reader, maxReadSize)
	_, err := protoReader.ReadMsg(&msg)
	return &msg, err
}

// WriteMessage writes a v1.0 message
func (p *V1Protocol) WriteMessage(writer io.Writer, msg interface{}) error {
	message, ok := msg.(*cometbftprivvalv1.Message)
	if !ok {
		return errors.New("invalid message type for v1 protocol")
	}
	protoWriter := protoio.NewDelimitedWriter(writer)
	_, err := protoWriter.WriteMsg(message)
	return err
}

// HandleRequest handles a v1.0 request
func (p *V1Protocol) HandleRequest(ctx context.Context, req interface{}, privVal PrivValidator, chainID, address string, logger cometlog.Logger) (interface{}, error) {
	message, ok := req.(*cometbftprivvalv1.Message)
	if !ok {
		return nil, errors.New("invalid request type for v1 protocol")
	}

	switch typedReq := message.Sum.(type) {
	case *cometbftprivvalv1.Message_SignVoteRequest:
		return p.handleSignVoteRequest(ctx, chainID, typedReq.SignVoteRequest, privVal, logger, address)
	case *cometbftprivvalv1.Message_SignProposalRequest:
		return p.handleSignProposalRequest(ctx, chainID, typedReq.SignProposalRequest.Proposal, privVal, logger, address)
	case *cometbftprivvalv1.Message_PubKeyRequest:
		return p.handlePubKeyRequest(ctx, chainID, privVal, logger, address)
	case *cometbftprivvalv1.Message_PingRequest:
		return p.handlePingRequest()
	case *cometbftprivvalv1.Message_SignBytesRequest:
		return p.handleSignBytesRequest(ctx, chainID, typedReq.SignBytesRequest, privVal, logger, address)
	default:
		logger.Error("Unknown request", "err", fmt.Errorf("%v", typedReq))
		return &cometbftprivvalv1.Message{}, nil
	}
}

func (p *V1Protocol) handleSignVoteRequest(ctx context.Context, chainID string, req *cometbftprivvalv1.SignVoteRequest, privVal PrivValidator, logger cometlog.Logger, address string) (*cometbftprivvalv1.Message, error) {
	msgSum := &cometbftprivvalv1.Message_SignedVoteResponse{SignedVoteResponse: &cometbftprivvalv1.SignedVoteResponse{
		Vote:  cometbfttypesv1.Vote{},
		Error: nil,
	}}

	// Check for nil vote
	if req.Vote == nil {
		msgSum.SignedVoteResponse.Error = &cometbftprivvalv1.RemoteSignerError{
			Code:        1,
			Description: "vote cannot be nil",
		}
		return &cometbftprivvalv1.Message{Sum: msgSum}, nil
	}

	// Convert v1 Vote to legacy format for signing
	legacyVote := &cometproto.Vote{
		Type:             cometproto.SignedMsgType(req.Vote.Type),
		Height:           req.Vote.Height,
		Round:            req.Vote.Round,
		BlockID: cometproto.BlockID{
			Hash: req.Vote.BlockID.Hash,
			PartSetHeader: cometproto.PartSetHeader{
				Total: req.Vote.BlockID.PartSetHeader.Total,
				Hash:  req.Vote.BlockID.PartSetHeader.Hash,
			},
		},
		Timestamp:        req.Vote.Timestamp,
		ValidatorAddress: req.Vote.ValidatorAddress,
		ValidatorIndex:   req.Vote.ValidatorIndex,
		Extension:        req.Vote.Extension,
	}

	sig, voteExtSig, _, err := SignAndTrack(
		ctx,
		logger,
		privVal,
		chainID,
		VoteToBlock(chainID, legacyVote),
	)
	if err != nil {
		msgSum.SignedVoteResponse.Error = getRemoteSignerErrorV1(err)
		return &cometbftprivvalv1.Message{Sum: msgSum}, nil
	}

	msgSum.SignedVoteResponse.Vote.Timestamp = req.Vote.Timestamp
	msgSum.SignedVoteResponse.Vote.Signature = sig
	
	// CRITICAL: Vote extensions are only allowed for non-nil precommits
	// - NOT allowed for prevotes  
	// - NOT allowed for nil precommits (BlockID.Hash is empty)
	isPrecommit := req.Vote.Type == cometbfttypesv1.SignedMsgType(cometproto.PrecommitType)
	isNonNilBlock := len(req.Vote.BlockID.Hash) > 0
	
	if !req.SkipExtensionSigning && len(voteExtSig) > 0 && isPrecommit && isNonNilBlock {
		msgSum.SignedVoteResponse.Vote.ExtensionSignature = voteExtSig
	}
	return &cometbftprivvalv1.Message{Sum: msgSum}, nil
}

func (p *V1Protocol) handleSignProposalRequest(ctx context.Context, chainID string, proposal *cometbfttypesv1.Proposal, privVal PrivValidator, logger cometlog.Logger, address string) (*cometbftprivvalv1.Message, error) {
	msgSum := &cometbftprivvalv1.Message_SignedProposalResponse{
		SignedProposalResponse: &cometbftprivvalv1.SignedProposalResponse{
			Proposal: cometbfttypesv1.Proposal{},
			Error:    nil,
		},
	}

	// Check for nil proposal
	if proposal == nil {
		msgSum.SignedProposalResponse.Error = &cometbftprivvalv1.RemoteSignerError{
			Code:        1,
			Description: "proposal cannot be nil",
		}
		return &cometbftprivvalv1.Message{Sum: msgSum}, nil
	}

	// Convert v1 Proposal to legacy format for signing
	legacyProposal := &cometproto.Proposal{
		Type:     cometproto.SignedMsgType(proposal.Type),
		Height:   proposal.Height,
		Round:    proposal.Round,
		PolRound: proposal.PolRound,
		BlockID: cometproto.BlockID{
			Hash: proposal.BlockID.Hash,
			PartSetHeader: cometproto.PartSetHeader{
				Total: proposal.BlockID.PartSetHeader.Total,
				Hash:  proposal.BlockID.PartSetHeader.Hash,
			},
		},
		Timestamp: proposal.Timestamp,
	}

	signature, _, timestamp, err := SignAndTrack(
		ctx,
		logger,
		privVal,
		chainID,
		ProposalToBlock(chainID, legacyProposal),
	)
	if err != nil {
		msgSum.SignedProposalResponse.Error = getRemoteSignerErrorV1(err)
		return &cometbftprivvalv1.Message{Sum: msgSum}, nil
	}

	msgSum.SignedProposalResponse.Proposal.Timestamp = timestamp
	msgSum.SignedProposalResponse.Proposal.Signature = signature
	return &cometbftprivvalv1.Message{Sum: msgSum}, nil
}

func (p *V1Protocol) handlePubKeyRequest(ctx context.Context, chainID string, privVal PrivValidator, logger cometlog.Logger, address string) (*cometbftprivvalv1.Message, error) {
	totalPubKeyRequests.WithLabelValues(chainID).Inc()
	msgSum := &cometbftprivvalv1.Message_PubKeyResponse{PubKeyResponse: &cometbftprivvalv1.PubKeyResponse{
		Error: nil,
	}}

	pubKey, err := privVal.GetPubKey(ctx, chainID)
	if err != nil {
		logger.Error(
			"Failed to get Pub Key",
			"chain_id", chainID,
			"node", address,
			"error", err,
		)
		msgSum.PubKeyResponse.Error = getRemoteSignerErrorV1(err)
		return &cometbftprivvalv1.Message{Sum: msgSum}, nil
	}

	// In v1.0, public key is sent as raw bytes with type information
	msgSum.PubKeyResponse.PubKeyBytes = pubKey
	msgSum.PubKeyResponse.PubKeyType = "ed25519"
	return &cometbftprivvalv1.Message{Sum: msgSum}, nil
}

func (p *V1Protocol) handlePingRequest() (*cometbftprivvalv1.Message, error) {
	return &cometbftprivvalv1.Message{
		Sum: &cometbftprivvalv1.Message_PingResponse{
			PingResponse: &cometbftprivvalv1.PingResponse{},
		},
	}, nil
}

func (p *V1Protocol) handleSignBytesRequest(ctx context.Context, chainID string, req *cometbftprivvalv1.SignBytesRequest, privVal PrivValidator, logger cometlog.Logger, address string) (*cometbftprivvalv1.Message, error) {
	msgSum := &cometbftprivvalv1.Message_SignBytesResponse{
		SignBytesResponse: &cometbftprivvalv1.SignBytesResponse{
			Error: nil,
		},
	}

	// For now, we don't support signing arbitrary bytes
	msgSum.SignBytesResponse.Error = getRemoteSignerErrorV1(errors.New("signing arbitrary bytes not supported"))
	return &cometbftprivvalv1.Message{Sum: msgSum}, nil
}

func getRemoteSignerErrorV1(err error) *cometbftprivvalv1.RemoteSignerError {
	if err == nil {
		return nil
	}
	return &cometbftprivvalv1.RemoteSignerError{
		Code:        0,
		Description: err.Error(),
	}
}

func getRemoteSignerErrorLegacy(err error) *cometprotoprivval.RemoteSignerError {
	if err == nil {
		return nil
	}
	return &cometprotoprivval.RemoteSignerError{
		Code:        0,
		Description: err.Error(),
	}
}

// NewPrivValProtocol creates a new protocol handler based on the version
func NewPrivValProtocol(version ProtocolVersion) (PrivValProtocol, error) {
	switch version {
	case ProtocolVersionLegacy:
		return &LegacyProtocol{}, nil
	case ProtocolVersionV1:
		return &V1Protocol{}, nil
	default:
		return nil, fmt.Errorf("unsupported protocol version: %s", version)
	}
}
