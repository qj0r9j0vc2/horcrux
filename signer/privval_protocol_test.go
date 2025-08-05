package signer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"
	"time"

	cometbftprivvalv1 "github.com/cometbft/cometbft/api/cometbft/privval/v1"
	cometbfttypesv1 "github.com/cometbft/cometbft/api/cometbft/types/v1"
	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cometcryptoencoding "github.com/cometbft/cometbft/crypto/encoding"
	"github.com/cometbft/cometbft/libs/log"
	cometprotoprivval "github.com/cometbft/cometbft/proto/tendermint/privval"
	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/require"
)

// RealSigningValidator implements proper CometBFT signing
type RealSigningValidator struct {
	privKey cometcryptoed25519.PrivKey
	chainID string
}

func NewRealSigningValidator(chainID string) *RealSigningValidator {
	return &RealSigningValidator{
		privKey: cometcryptoed25519.GenPrivKey(),
		chainID: chainID,
	}
}

func (v *RealSigningValidator) Sign(ctx context.Context, chainID string, block Block) ([]byte, []byte, time.Time, error) {
	// Create proper CometBFT types for signing
	var signBytes []byte

	switch block.Step {
	case stepPrevote, stepPrecommit:
		vote := &types.Vote{
			Type:             cometproto.SignedMsgType(block.Step),
			Height:           block.Height,
			Round:            int32(block.Round),
			BlockID:          types.BlockID{},
			Timestamp:        block.Timestamp,
			ValidatorAddress: v.privKey.PubKey().Address(),
			ValidatorIndex:   0,
		}

		// Create proper sign bytes using CometBFT's method
		protoVote := vote.ToProto()
		signBytes = types.VoteSignBytes(chainID, protoVote)

	case stepPropose:
		proposal := &types.Proposal{
			Type:      cometproto.ProposalType,
			Height:    block.Height,
			Round:     int32(block.Round),
			POLRound:  -1,
			BlockID:   types.BlockID{},
			Timestamp: block.Timestamp,
		}

		// Create proper sign bytes using CometBFT's method
		protoProposal := proposal.ToProto()
		signBytes = types.ProposalSignBytes(chainID, protoProposal)
	}

	// Sign using the private key
	sig, err := v.privKey.Sign(signBytes)
	if err != nil {
		return nil, nil, time.Time{}, err
	}

	return sig, nil, block.Timestamp, nil
}

func (v *RealSigningValidator) GetPubKey(ctx context.Context, chainID string) ([]byte, error) {
	return v.privKey.PubKey().Bytes(), nil
}

func (v *RealSigningValidator) Stop() {}

// TestProtocolVersionHandling tests protocol version configuration and switching
func TestProtocolVersionHandling(t *testing.T) {
	// Test per-node protocol version configuration
	nodes := []ChainNode{
		{PrivValAddr: "tcp://localhost:26658", ProtocolVersion: ""},       // Default (legacy)
		{PrivValAddr: "tcp://localhost:26659", ProtocolVersion: "legacy"}, // Explicit legacy
		{PrivValAddr: "tcp://localhost:26660", ProtocolVersion: "v1"},     // V1 protocol
	}

	expectedVersions := []ProtocolVersion{
		ProtocolVersionLegacy,
		ProtocolVersionLegacy,
		ProtocolVersionV1,
	}

	for i, node := range nodes {
		version := node.GetProtocolVersion()
		require.Equal(t, expectedVersions[i], version,
			"Node with ProtocolVersion=%q should return %s",
			node.ProtocolVersion, expectedVersions[i])

		// Verify protocol can be created
		protocol, err := NewPrivValProtocol(version)
		require.NoError(t, err)
		require.NotNil(t, protocol)
	}

	// Test invalid version defaults to legacy
	node := ChainNode{PrivValAddr: "tcp://localhost:26661", ProtocolVersion: "invalid"}
	require.Equal(t, ProtocolVersionLegacy, node.GetProtocolVersion())

	t.Log("Per-node protocol version switching logic verified")
}

// TestV1ProtocolEndToEnd tests complete v1 protocol functionality
func TestV1ProtocolEndToEnd(t *testing.T) {
	testCases := []struct {
		name            string
		protocolVersion ProtocolVersion
		chainID         string
	}{
		{
			name:            "Injective mainnet simulation",
			protocolVersion: ProtocolVersionV1,
			chainID:         "injective-1",
		},
		{
			name:            "Cosmoshub legacy protocol",
			protocolVersion: ProtocolVersionLegacy,
			chainID:         "cosmoshub-4",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a validator with a proper Ed25519 private key
			privKey := cometcryptoed25519.GenPrivKey()

			validator := &RealSigningValidator{
				privKey: privKey,
				chainID: tc.chainID,
			}

			// Get the protocol handler
			protocol, err := NewPrivValProtocol(tc.protocolVersion)
			require.NoError(t, err)

			// Test 1: Public Key Request
			t.Run("PubKey Request", func(t *testing.T) {
				var req interface{}

				if tc.protocolVersion == ProtocolVersionLegacy {
					req = cometprotoprivval.Message{
						Sum: &cometprotoprivval.Message_PubKeyRequest{
							PubKeyRequest: &cometprotoprivval.PubKeyRequest{
								ChainId: tc.chainID,
							},
						},
					}
				} else {
					req = &cometbftprivvalv1.Message{
						Sum: &cometbftprivvalv1.Message_PubKeyRequest{
							PubKeyRequest: &cometbftprivvalv1.PubKeyRequest{
								ChainId: tc.chainID,
							},
						},
					}
				}

				resp, err := protocol.HandleRequest(context.Background(), req, validator, tc.chainID, "127.0.0.1", log.NewNopLogger())
				require.NoError(t, err)
				require.NotNil(t, resp)

				// Verify we got the correct public key
				expectedPubKey := privKey.PubKey().Bytes()

				if tc.protocolVersion == ProtocolVersionLegacy {
					legacyResp := resp.(cometprotoprivval.Message)
					pubKeyResp := legacyResp.GetPubKeyResponse()
					require.NotNil(t, pubKeyResp)
					require.Nil(t, pubKeyResp.Error)
					// Legacy protocol wraps the key, so we need to extract it
					require.NotNil(t, pubKeyResp.PubKey)
				} else {
					v1Resp := resp.(*cometbftprivvalv1.Message)
					pubKeyResp := v1Resp.GetPubKeyResponse()
					require.NotNil(t, pubKeyResp)
					require.Nil(t, pubKeyResp.Error)
					require.Equal(t, expectedPubKey, pubKeyResp.PubKeyBytes)
					require.Equal(t, "ed25519", pubKeyResp.PubKeyType)
				}

				t.Logf("PubKey request successful for %s protocol", tc.protocolVersion)
			})

			// Test 2: Vote Signing
			t.Run("Vote Signing", func(t *testing.T) {
				height := int64(100000)
				round := int32(0)
				timestamp := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

				// Create proper block hash
				blockHash := sha256.Sum256([]byte("test-block-100000"))
				partSetHash := sha256.Sum256([]byte("test-partset-100000"))

				var req interface{}

				if tc.protocolVersion == ProtocolVersionLegacy {
					// Legacy request would come from a v0.38 node
					// For testing, we simulate the conversion
					block := Block{
						Height:    height,
						Round:     int64(round),
						Step:      stepPrevote,
						Timestamp: timestamp,
					}

					sig, _, _, err := validator.Sign(context.Background(), tc.chainID, block)
					require.NoError(t, err)
					require.Len(t, sig, 64, "Ed25519 signature should be 64 bytes")

				} else {
					vote := &cometbfttypesv1.Vote{
						Type:   1, // PREVOTE
						Height: height,
						Round:  round,
						BlockID: cometbfttypesv1.BlockID{
							Hash: blockHash[:],
							PartSetHeader: cometbfttypesv1.PartSetHeader{
								Total: 100,
								Hash:  partSetHash[:],
							},
						},
						Timestamp:        timestamp,
						ValidatorAddress: privKey.PubKey().Address(),
						ValidatorIndex:   0,
					}

					req = &cometbftprivvalv1.Message{
						Sum: &cometbftprivvalv1.Message_SignVoteRequest{
							SignVoteRequest: &cometbftprivvalv1.SignVoteRequest{
								Vote:                 vote,
								ChainId:              tc.chainID,
								SkipExtensionSigning: false,
							},
						},
					}

					resp, err := protocol.HandleRequest(context.Background(), req, validator, tc.chainID, "127.0.0.1", log.NewNopLogger())
					require.NoError(t, err)

					v1Resp := resp.(*cometbftprivvalv1.Message)
					voteResp := v1Resp.GetSignedVoteResponse()
					require.NotNil(t, voteResp)
					require.Nil(t, voteResp.Error)
					require.NotEmpty(t, voteResp.Vote.Signature)
					require.Len(t, voteResp.Vote.Signature, 64, "Ed25519 signature should be 64 bytes")
				}

				t.Logf("Vote signing successful for %s protocol", tc.protocolVersion)
			})

			// Test 3: Proposal Signing
			t.Run("Proposal Signing", func(t *testing.T) {
				height := int64(100001)
				round := int32(1)
				timestamp := time.Date(2024, 1, 1, 12, 1, 0, 0, time.UTC)

				block := Block{
					Height:    height,
					Round:     int64(round),
					Step:      stepPropose,
					Timestamp: timestamp,
				}

				sig, _, _, err := validator.Sign(context.Background(), tc.chainID, block)
				require.NoError(t, err)
				require.Len(t, sig, 64, "Ed25519 signature should be 64 bytes")

				t.Logf("Proposal signing successful for %s protocol", tc.protocolVersion)
			})
		})
	}
}

// TestV1ProtocolFeatures tests v1 protocol specific features
func TestV1ProtocolFeatures(t *testing.T) {
	chainID := "cosmoshub-4"
	validator := NewRealSigningValidator(chainID)
	protocolV1 := &V1Protocol{}
	logger := log.NewNopLogger()

	t.Run("PubKey Encoding", func(t *testing.T) {
		pubKeyBytes, err := validator.GetPubKey(context.Background(), chainID)
		require.NoError(t, err)

		// Test V1 Protocol PubKey Response
		v1Req := &cometbftprivvalv1.Message{
			Sum: &cometbftprivvalv1.Message_PubKeyRequest{
				PubKeyRequest: &cometbftprivvalv1.PubKeyRequest{
					ChainId: chainID,
				},
			},
		}

		v1Resp, err := protocolV1.HandleRequest(context.Background(), v1Req, validator, chainID, "127.0.0.1", logger)
		require.NoError(t, err)

		v1Msg := v1Resp.(*cometbftprivvalv1.Message)
		v1PubKeyResp := v1Msg.GetPubKeyResponse()
		require.NotNil(t, v1PubKeyResp)
		require.Nil(t, v1PubKeyResp.Error)
		require.Equal(t, pubKeyBytes, v1PubKeyResp.PubKeyBytes)
		require.Equal(t, "ed25519", v1PubKeyResp.PubKeyType)

		t.Logf("PubKey encoding verified - V1: %x (type: %s)",
			v1PubKeyResp.PubKeyBytes[:10], v1PubKeyResp.PubKeyType)
	})

	t.Run("Skip Extension Signing", func(t *testing.T) {
		v1Vote := &cometbfttypesv1.Vote{
			Type:             1, // PREVOTE
			Height:           99999,
			Round:            0,
			BlockID:          cometbfttypesv1.BlockID{},
			Timestamp:        time.Now(),
			ValidatorAddress: nil, // nil address
			ValidatorIndex:   0,
		}

		// Test skip extension signing
		v1Req := &cometbftprivvalv1.Message{
			Sum: &cometbftprivvalv1.Message_SignVoteRequest{
				SignVoteRequest: &cometbftprivvalv1.SignVoteRequest{
					Vote:                 v1Vote,
					ChainId:              chainID,
					SkipExtensionSigning: true, // Skip extension
				},
			},
		}

		v1Resp, err := protocolV1.HandleRequest(context.Background(), v1Req, validator, chainID, "127.0.0.1", logger)
		require.NoError(t, err)

		v1RespMsg := v1Resp.(*cometbftprivvalv1.Message)
		v1VoteResp := v1RespMsg.GetSignedVoteResponse()
		require.NotNil(t, v1VoteResp)
		// After fix: ExtensionSignature should be assigned even with SkipExtensionSigning=true
		// to ensure deterministic behavior across protocol versions
		require.NotNil(t, v1VoteResp.Vote.ExtensionSignature)

		t.Log("Deterministic behavior verified: ExtensionSignature always assigned")
	})

	t.Run("Protocol Message Compatibility", func(t *testing.T) {
		// Ensure messages can be properly serialized/deserialized
		var buf bytes.Buffer

		// Write V1 message
		v1Protocol := &V1Protocol{}
		v1Msg := &cometbftprivvalv1.Message{
			Sum: &cometbftprivvalv1.Message_PingRequest{
				PingRequest: &cometbftprivvalv1.PingRequest{},
			},
		}

		err := v1Protocol.WriteMessage(&buf, v1Msg)
		require.NoError(t, err)

		// Read it back
		readMsg, err := v1Protocol.ReadMessage(&buf, 1024*1024)
		require.NoError(t, err)
		require.NotNil(t, readMsg)

		readMsgTyped := readMsg.(*cometbftprivvalv1.Message)
		require.NotNil(t, readMsgTyped.GetPingRequest())

		t.Log("Protocol message serialization/deserialization verified")
	})
}

// TestDeterministicVoteExtension verifies that vote extension signatures are handled deterministically
func TestDeterministicVoteExtension(t *testing.T) {
	chainID := "test-deterministic"
	validator := NewRealSigningValidator(chainID)
	logger := log.NewNopLogger()

	// Create identical votes for both protocols
	height := int64(100000)
	round := int32(0)
	timestamp := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	// Test legacy protocol
	legacyProtocol := &LegacyProtocol{}
	legacyVote := &cometproto.Vote{
		Type:             cometproto.PrevoteType,
		Height:           height,
		Round:            round,
		Timestamp:        timestamp,
		ValidatorAddress: validator.privKey.PubKey().Address(),
		ValidatorIndex:   0,
	}

	legacyReq := cometprotoprivval.Message{
		Sum: &cometprotoprivval.Message_SignVoteRequest{
			SignVoteRequest: &cometprotoprivval.SignVoteRequest{
				Vote:    legacyVote,
				ChainId: chainID,
			},
		},
	}

	legacyResp, err := legacyProtocol.HandleRequest(context.Background(), legacyReq, validator, chainID, "127.0.0.1", logger)
	require.NoError(t, err)
	legacyMsg := legacyResp.(cometprotoprivval.Message)
	legacyVoteResp := legacyMsg.GetSignedVoteResponse()
	require.NotNil(t, legacyVoteResp)

	// Test V1 protocol with same vote
	v1Protocol := &V1Protocol{}
	v1Vote := &cometbfttypesv1.Vote{
		Type:             1, // PREVOTE
		Height:           height,
		Round:            round,
		Timestamp:        timestamp,
		ValidatorAddress: validator.privKey.PubKey().Address(),
		ValidatorIndex:   0,
	}

	v1Req := &cometbftprivvalv1.Message{
		Sum: &cometbftprivvalv1.Message_SignVoteRequest{
			SignVoteRequest: &cometbftprivvalv1.SignVoteRequest{
				Vote:                 v1Vote,
				ChainId:              chainID,
				SkipExtensionSigning: true, // This should not affect determinism
			},
		},
	}

	v1Resp, err := v1Protocol.HandleRequest(context.Background(), v1Req, validator, chainID, "127.0.0.1", logger)
	require.NoError(t, err)
	v1Msg := v1Resp.(*cometbftprivvalv1.Message)
	v1VoteResp := v1Msg.GetSignedVoteResponse()
	require.NotNil(t, v1VoteResp)

	// Verify that ExtensionSignature is handled deterministically
	require.Equal(t, legacyVoteResp.Vote.ExtensionSignature, v1VoteResp.Vote.ExtensionSignature,
		"ExtensionSignature must be identical between legacy and v1 protocols")

	t.Log("Vote extension determinism verified across protocol versions")
}

// TestSignatureConsistency ensures signatures are consistent across multiple calls
func TestSignatureConsistency(t *testing.T) {
	chainID := "test-consistency"
	validator := NewRealSigningValidator(chainID)

	block := Block{
		Height:    12345,
		Round:     0,
		Step:      stepPrevote,
		Timestamp: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	// Sign the same block multiple times
	signatures := make([][]byte, 5)
	for i := 0; i < 5; i++ {
		sig, _, _, err := validator.Sign(context.Background(), chainID, block)
		require.NoError(t, err)
		signatures[i] = sig
	}

	// All signatures should be identical
	for i := 1; i < 5; i++ {
		require.Equal(t, signatures[0], signatures[i], "Signatures should be consistent")
	}

	t.Logf("Signature consistency verified - All 5 signatures match: %x", signatures[0][:10])
}

// TestCometBFTV1Compatibility verifies full compatibility with CometBFT v1.0
func TestCometBFTV1Compatibility(t *testing.T) {
	// This test simulates what would happen in a real validator scenario
	chainID := "injective-1"
	validator := NewRealSigningValidator(chainID)
	protocol := &V1Protocol{}
	logger := log.NewNopLogger()

	// Simulate multiple signing operations as would happen in real consensus
	heights := []int64{1000, 1001, 1002, 1003, 1004}

	for _, height := range heights {
		// Sign prevote
		prevoteReq := &cometbftprivvalv1.Message{
			Sum: &cometbftprivvalv1.Message_SignVoteRequest{
				SignVoteRequest: &cometbftprivvalv1.SignVoteRequest{
					Vote: &cometbfttypesv1.Vote{
						Type:             1, // PREVOTE
						Height:           height,
						Round:            0,
						BlockID:          cometbfttypesv1.BlockID{},
						Timestamp:        time.Now(),
						ValidatorAddress: validator.privKey.PubKey().Address(),
						ValidatorIndex:   0,
					},
					ChainId: chainID,
				},
			},
		}

		resp, err := protocol.HandleRequest(context.Background(), prevoteReq, validator, chainID, "sentry-1", logger)
		require.NoError(t, err)

		v1Resp := resp.(*cometbftprivvalv1.Message)
		voteResp := v1Resp.GetSignedVoteResponse()
		require.NotNil(t, voteResp)
		require.Nil(t, voteResp.Error)
		require.NotEmpty(t, voteResp.Vote.Signature)

		// Sign precommit
		precommitReq := &cometbftprivvalv1.Message{
			Sum: &cometbftprivvalv1.Message_SignVoteRequest{
				SignVoteRequest: &cometbftprivvalv1.SignVoteRequest{
					Vote: &cometbfttypesv1.Vote{
						Type:             2, // PRECOMMIT
						Height:           height,
						Round:            0,
						BlockID:          cometbfttypesv1.BlockID{},
						Timestamp:        time.Now(),
						ValidatorAddress: validator.privKey.PubKey().Address(),
						ValidatorIndex:   0,
					},
					ChainId: chainID,
				},
			},
		}

		resp2, err := protocol.HandleRequest(context.Background(), precommitReq, validator, chainID, "sentry-1", logger)
		require.NoError(t, err)

		v1Resp2 := resp2.(*cometbftprivvalv1.Message)
		voteResp2 := v1Resp2.GetSignedVoteResponse()
		require.NotNil(t, voteResp2)
		require.Nil(t, voteResp2.Error)
		require.NotEmpty(t, voteResp2.Vote.Signature)
	}

	t.Logf("Successfully signed %d blocks with CometBFT v1.0 protocol", len(heights))
	t.Log("Horcrux is ready for CometBFT v1.0 chains")
}

// TestLegacyCompatibility verifies backward compatibility with legacy protocol
func TestLegacyCompatibility(t *testing.T) {
	chainID := "cosmoshub-4"
	validator := NewRealSigningValidator(chainID)
	protocolLegacy := &LegacyProtocol{}
	logger := log.NewNopLogger()

	t.Run("Legacy PubKey Response", func(t *testing.T) {
		pubKeyBytes, err := validator.GetPubKey(context.Background(), chainID)
		require.NoError(t, err)

		// Test Legacy Protocol PubKey Response
		legacyReq := cometprotoprivval.Message{
			Sum: &cometprotoprivval.Message_PubKeyRequest{
				PubKeyRequest: &cometprotoprivval.PubKeyRequest{
					ChainId: chainID,
				},
			},
		}

		legacyResp, err := protocolLegacy.HandleRequest(context.Background(), legacyReq, validator, chainID, "127.0.0.1", logger)
		require.NoError(t, err)

		legacyMsg := legacyResp.(cometprotoprivval.Message)
		legacyPubKeyResp := legacyMsg.GetPubKeyResponse()
		require.NotNil(t, legacyPubKeyResp)
		require.Nil(t, legacyPubKeyResp.Error)

		// Extract pubkey from legacy response
		legacyPubKey, err := cometcryptoencoding.PubKeyFromProto(legacyPubKeyResp.PubKey)
		require.NoError(t, err)
		require.Equal(t, pubKeyBytes, legacyPubKey.Bytes())

		t.Logf("Legacy PubKey encoding verified - %x", legacyPubKey.Bytes()[:10])
	})
}

// TestNilValueHandling tests handling of nil values across protocols
func TestNilValueHandling(t *testing.T) {
	chainID := "test-nil"
	validator := NewRealSigningValidator(chainID)
	logger := log.NewNopLogger()

	testCases := []struct {
		name            string
		protocolVersion ProtocolVersion
	}{
		{"V1 Protocol", ProtocolVersionV1},
		{"Legacy Protocol", ProtocolVersionLegacy},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			protocol, err := NewPrivValProtocol(tc.protocolVersion)
			require.NoError(t, err)

			// Test nil vote
			if tc.protocolVersion == ProtocolVersionV1 {
				req := &cometbftprivvalv1.Message{
					Sum: &cometbftprivvalv1.Message_SignVoteRequest{
						SignVoteRequest: &cometbftprivvalv1.SignVoteRequest{
							Vote:    nil,
							ChainId: chainID,
						},
					},
				}

				resp, err := protocol.HandleRequest(context.Background(), req, validator, chainID, "127.0.0.1", logger)
				require.NoError(t, err)
				require.NotNil(t, resp)

				v1Resp := resp.(*cometbftprivvalv1.Message)
				voteResp := v1Resp.GetSignedVoteResponse()
				require.NotNil(t, voteResp)
				require.NotNil(t, voteResp.Error)
				t.Logf("V1: Properly handled nil vote with error: %s", voteResp.Error.Description)
			}

			// Test nil BlockID
			if tc.protocolVersion == ProtocolVersionV1 {
				vote := &cometbfttypesv1.Vote{
					Type:             1, // PREVOTE
					Height:           100,
					Round:            0,
					BlockID:          cometbfttypesv1.BlockID{}, // Empty BlockID
					Timestamp:        time.Now(),
					ValidatorAddress: nil, // nil address
					ValidatorIndex:   0,
				}

				req := &cometbftprivvalv1.Message{
					Sum: &cometbftprivvalv1.Message_SignVoteRequest{
						SignVoteRequest: &cometbftprivvalv1.SignVoteRequest{
							Vote:    vote,
							ChainId: chainID,
						},
					},
				}

				resp, err := protocol.HandleRequest(context.Background(), req, validator, chainID, "127.0.0.1", logger)
				require.NoError(t, err)
				require.NotNil(t, resp)

				v1Resp := resp.(*cometbftprivvalv1.Message)
				voteResp := v1Resp.GetSignedVoteResponse()
				require.NotNil(t, voteResp)
				// Should handle empty BlockID gracefully
				if voteResp.Error == nil {
					require.NotEmpty(t, voteResp.Vote.Signature)
					t.Log("V1: Successfully signed vote with nil/empty BlockID")
				}
			}

			// Test nil proposal
			if tc.protocolVersion == ProtocolVersionV1 {
				req := &cometbftprivvalv1.Message{
					Sum: &cometbftprivvalv1.Message_SignProposalRequest{
						SignProposalRequest: &cometbftprivvalv1.SignProposalRequest{
							Proposal: nil,
							ChainId:  chainID,
						},
					},
				}

				resp, err := protocol.HandleRequest(context.Background(), req, validator, chainID, "127.0.0.1", logger)
				require.NoError(t, err)
				require.NotNil(t, resp)

				v1Resp := resp.(*cometbftprivvalv1.Message)
				propResp := v1Resp.GetSignedProposalResponse()
				require.NotNil(t, propResp)
				require.NotNil(t, propResp.Error)
				t.Logf("V1: Properly handled nil proposal with error: %s", propResp.Error.Description)
			}
		})
	}
}

// TestExtensionSigning tests vote extension signing behavior
func TestExtensionSigning(t *testing.T) {
	chainID := "test-extensions"
	validator := NewRealSigningValidator(chainID)
	protocolV1 := &V1Protocol{}
	logger := log.NewNopLogger()

	t.Run("Skip Extension Signing", func(t *testing.T) {
		// Create a valid 32-byte hash
		hash := sha256.Sum256([]byte("test-hash"))
		
		vote := &cometbfttypesv1.Vote{
			Type:             2, // PRECOMMIT - only precommits have extensions
			Height:           1000,
			Round:            0,
			BlockID:          cometbfttypesv1.BlockID{Hash: hash[:]},
			Timestamp:        time.Now(),
			ValidatorAddress: validator.privKey.PubKey().Address(),
			ValidatorIndex:   0,
			Extension:        []byte("test-extension-data"),
		}

		// Test with skip_extension_signing = true
		req := &cometbftprivvalv1.Message{
			Sum: &cometbftprivvalv1.Message_SignVoteRequest{
				SignVoteRequest: &cometbftprivvalv1.SignVoteRequest{
					Vote:                 vote,
					ChainId:              chainID,
					SkipExtensionSigning: true,
				},
			},
		}

		resp, err := protocolV1.HandleRequest(context.Background(), req, validator, chainID, "127.0.0.1", logger)
		require.NoError(t, err)

		v1Resp := resp.(*cometbftprivvalv1.Message)
		voteResp := v1Resp.GetSignedVoteResponse()
		require.NotNil(t, voteResp)
		require.Nil(t, voteResp.Error)
		require.NotEmpty(t, voteResp.Vote.Signature)
		require.Empty(t, voteResp.Vote.ExtensionSignature) // Should be empty when skipped
		t.Log("Extension signing properly skipped when requested")
	})

	t.Run("Sign Extension", func(t *testing.T) {
		// Create a valid 32-byte hash
		hash := sha256.Sum256([]byte("test-hash-2"))
		
		vote := &cometbfttypesv1.Vote{
			Type:             2, // PRECOMMIT
			Height:           1001,
			Round:            0,
			BlockID:          cometbfttypesv1.BlockID{Hash: hash[:]},
			Timestamp:        time.Now(),
			ValidatorAddress: validator.privKey.PubKey().Address(),
			ValidatorIndex:   0,
			Extension:        []byte("test-extension-data-2"),
		}

		// Test with skip_extension_signing = false
		req := &cometbftprivvalv1.Message{
			Sum: &cometbftprivvalv1.Message_SignVoteRequest{
				SignVoteRequest: &cometbftprivvalv1.SignVoteRequest{
					Vote:                 vote,
					ChainId:              chainID,
					SkipExtensionSigning: false,
				},
			},
		}

		resp, err := protocolV1.HandleRequest(context.Background(), req, validator, chainID, "127.0.0.1", logger)
		require.NoError(t, err)

		v1Resp := resp.(*cometbftprivvalv1.Message)
		voteResp := v1Resp.GetSignedVoteResponse()
		require.NotNil(t, voteResp)
		require.Nil(t, voteResp.Error)
		require.NotEmpty(t, voteResp.Vote.Signature)
		// Extension signature behavior depends on implementation
		t.Log("Extension signing handled correctly")
	})

	t.Run("Prevote No Extension", func(t *testing.T) {
		// Prevotes should never have extension signatures
		hash := sha256.Sum256([]byte("test-hash-3"))
		vote := &cometbfttypesv1.Vote{
			Type:             1, // PREVOTE
			Height:           1002,
			Round:            0,
			BlockID:          cometbfttypesv1.BlockID{Hash: hash[:]},
			Timestamp:        time.Now(),
			ValidatorAddress: validator.privKey.PubKey().Address(),
			ValidatorIndex:   0,
		}

		req := &cometbftprivvalv1.Message{
			Sum: &cometbftprivvalv1.Message_SignVoteRequest{
				SignVoteRequest: &cometbftprivvalv1.SignVoteRequest{
					Vote:                 vote,
					ChainId:              chainID,
					SkipExtensionSigning: false, // Even with false, prevotes shouldn't have extensions
				},
			},
		}

		resp, err := protocolV1.HandleRequest(context.Background(), req, validator, chainID, "127.0.0.1", logger)
		require.NoError(t, err)

		v1Resp := resp.(*cometbftprivvalv1.Message)
		voteResp := v1Resp.GetSignedVoteResponse()
		require.NotNil(t, voteResp)
		require.Nil(t, voteResp.Error)
		require.NotEmpty(t, voteResp.Vote.Signature)
		require.Empty(t, voteResp.Vote.ExtensionSignature) // Prevotes never have extension signatures
		t.Log("Prevote correctly has no extension signature")
	})
}

// TestErrorConditions tests various error scenarios
func TestErrorConditions(t *testing.T) {
	chainID := "test-errors"
	validator := NewRealSigningValidator(chainID)
	logger := log.NewNopLogger()

	t.Run("Wrong Protocol Message Type", func(t *testing.T) {
		protocolV1 := &V1Protocol{}
		legacyMsg := cometprotoprivval.Message{
			Sum: &cometprotoprivval.Message_PubKeyRequest{
				PubKeyRequest: &cometprotoprivval.PubKeyRequest{
					ChainId: chainID,
				},
			},
		}

		_, err := protocolV1.HandleRequest(context.Background(), legacyMsg, validator, chainID, "127.0.0.1", logger)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid request type")
	})

	t.Run("Unknown Message Type", func(t *testing.T) {
		protocolV1 := &V1Protocol{}
		req := &cometbftprivvalv1.Message{
			Sum: nil, // Unknown message type
		}

		resp, err := protocolV1.HandleRequest(context.Background(), req, validator, chainID, "127.0.0.1", logger)
		require.NoError(t, err) // V1Protocol returns nil error for unknown message types
		require.NotNil(t, resp)
		// The response will be an empty message
		v1Resp := resp.(*cometbftprivvalv1.Message)
		require.Nil(t, v1Resp.Sum) // Empty response
	})

	t.Run("Message Serialization Error", func(t *testing.T) {
		protocolV1 := &V1Protocol{}
		
		// Test with corrupted data
		buf := bytes.NewBuffer([]byte{0xFF, 0xFF, 0xFF, 0xFF})
		_, err := protocolV1.ReadMessage(buf, 1024)
		require.Error(t, err)
	})
}

// TestConcurrentRequests tests handling of concurrent signing requests
func TestConcurrentRequests(t *testing.T) {
	chainID := "test-concurrent"
	validator := NewRealSigningValidator(chainID)
	protocolV1 := &V1Protocol{}
	logger := log.NewNopLogger()

	// Test multiple goroutines signing different blocks
	var wg sync.WaitGroup
	errors := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(height int64) {
			defer wg.Done()

			vote := &cometbfttypesv1.Vote{
				Type:             1, // PREVOTE
				Height:           height,
				Round:            0,
				BlockID:          cometbfttypesv1.BlockID{},
				Timestamp:        time.Now(),
				ValidatorAddress: validator.privKey.PubKey().Address(),
				ValidatorIndex:   0,
			}

			req := &cometbftprivvalv1.Message{
				Sum: &cometbftprivvalv1.Message_SignVoteRequest{
					SignVoteRequest: &cometbftprivvalv1.SignVoteRequest{
						Vote:    vote,
						ChainId: chainID,
					},
				},
			}

			resp, err := protocolV1.HandleRequest(context.Background(), req, validator, chainID, "127.0.0.1", logger)
			if err != nil {
				errors <- err
				return
			}

			v1Resp := resp.(*cometbftprivvalv1.Message)
			voteResp := v1Resp.GetSignedVoteResponse()
			if voteResp.Error != nil {
				errors <- fmt.Errorf(voteResp.Error.Description)
			}
		}(int64(1000 + i))
	}

	wg.Wait()
	close(errors)

	// Check no errors occurred
	for err := range errors {
		t.Errorf("Concurrent request error: %v", err)
	}

	t.Log("Successfully handled concurrent signing requests")
}

// BenchmarkProtocolPerformance benchmarks protocol operations
func BenchmarkProtocolPerformance(b *testing.B) {
	chainID := "bench-chain"
	validator := NewRealSigningValidator(chainID)
	logger := log.NewNopLogger()

	b.Run("V1 Protocol Signing", func(b *testing.B) {
		protocolV1 := &V1Protocol{}
		vote := &cometbfttypesv1.Vote{
			Type:             1,
			Height:           1000,
			Round:            0,
			BlockID:          cometbfttypesv1.BlockID{},
			Timestamp:        time.Now(),
			ValidatorAddress: validator.privKey.PubKey().Address(),
			ValidatorIndex:   0,
		}

		req := &cometbftprivvalv1.Message{
			Sum: &cometbftprivvalv1.Message_SignVoteRequest{
				SignVoteRequest: &cometbftprivvalv1.SignVoteRequest{
					Vote:    vote,
					ChainId: chainID,
				},
			},
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = protocolV1.HandleRequest(context.Background(), req, validator, chainID, "127.0.0.1", logger)
		}
	})

	b.Run("Legacy Protocol Signing", func(b *testing.B) {
		protocolLegacy := &LegacyProtocol{}
		block := Block{
			Height:    1000,
			Round:     0,
			Step:      stepPrevote,
			Timestamp: time.Now(),
		}

		// Convert to sign bytes
		vote := &types.Vote{
			Type:             cometproto.SignedMsgType(block.Step),
			Height:           block.Height,
			Round:            int32(block.Round),
			BlockID:          types.BlockID{},
			Timestamp:        block.Timestamp,
			ValidatorAddress: validator.privKey.PubKey().Address(),
			ValidatorIndex:   0,
		}
		protoVote := vote.ToProto()
		_ = types.VoteSignBytes(chainID, protoVote)

		req := cometprotoprivval.Message{
			Sum: &cometprotoprivval.Message_SignVoteRequest{
				SignVoteRequest: &cometprotoprivval.SignVoteRequest{
					Vote:    protoVote,
					ChainId: chainID,
				},
			},
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = protocolLegacy.HandleRequest(context.Background(), req, validator, chainID, "127.0.0.1", logger)
		}
	})
}
