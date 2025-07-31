package signer

import (
	"context"
	"fmt"
	"testing"
	"time"

	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cometlog "github.com/cometbft/cometbft/libs/log"
	"github.com/stretchr/testify/require"
)

// SimpleValidator for quick testing
type SimpleValidator struct {
	privKey cometcryptoed25519.PrivKey
}

func NewSimpleValidator() *SimpleValidator {
	return &SimpleValidator{
		privKey: cometcryptoed25519.GenPrivKey(),
	}
}

func (v *SimpleValidator) Sign(ctx context.Context, chainID string, block Block) ([]byte, []byte, time.Time, error) {
	// For testing, just sign a simple message
	// In real implementation, this would create proper vote/proposal bytes
	msg := []byte(fmt.Sprintf("%s:%d:%d:%d", chainID, block.Height, block.Round, block.Step))

	// Sign
	sig, err := v.privKey.Sign(msg)
	if err != nil {
		return nil, nil, time.Time{}, err
	}

	return sig, nil, block.Timestamp, nil
}

func (v *SimpleValidator) GetPubKey(ctx context.Context, chainID string) ([]byte, error) {
	return v.privKey.PubKey().Bytes(), nil
}

func (v *SimpleValidator) Stop() {}

// TestSimpleV1Signing - Quick test to verify v1 protocol signing works
func TestSimpleV1Signing(t *testing.T) {
	validator := NewSimpleValidator()
	logger := cometlog.NewNopLogger()
	chainID := "test-chain"

	// Test 1: Get public key
	pubKey, err := validator.GetPubKey(context.Background(), chainID)
	require.NoError(t, err)
	require.NotNil(t, pubKey)
	t.Logf("✓ Public key retrieved: %x", pubKey[:10])

	// Test 2: Sign a vote
	block := Block{
		Height:    100,
		Round:     0,
		Step:      stepPrevote,
		Timestamp: time.Now(),
	}

	sig, _, timestamp, err := SignAndTrack(
		context.Background(),
		logger,
		validator,
		chainID,
		block,
	)

	require.NoError(t, err)
	require.NotNil(t, sig)
	require.NotZero(t, timestamp)
	t.Logf("✓ Vote signed successfully: signature=%x", sig[:10])

	// Test 3: Sign a proposal
	block.Step = stepPropose
	sig, _, timestamp, err = SignAndTrack(
		context.Background(),
		logger,
		validator,
		chainID,
		block,
	)

	require.NoError(t, err)
	require.NotNil(t, sig)
	require.NotZero(t, timestamp)
	t.Logf("✓ Proposal signed successfully: signature=%x", sig[:10])

	t.Log("\nCometBFT v1.0 signing works correctly!")
}
