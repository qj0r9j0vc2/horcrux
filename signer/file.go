package signer

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	cometjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/libs/protoio"
	"github.com/cometbft/cometbft/libs/tempfile"
	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/types"
)

//-------------------------------------------------------------------------------

// FilePVKey stores the immutable part of PrivValidator.
type FilePVKey struct {
	Address types.Address  `json:"address"`
	PubKey  crypto.PubKey  `json:"pub_key"`
	PrivKey crypto.PrivKey `json:"priv_key"`

	filePath string
}

// Save persists the FilePVKey to its filePath.
func (pvKey FilePVKey) Save() {
	outFile := pvKey.filePath
	if outFile == "" {
		panic("cannot save PrivValidator key: filePath not set")
	}

	jsonBytes, err := cometjson.MarshalIndent(pvKey, "", "  ")
	if err != nil {
		panic(err)
	}

	if err := tempfile.WriteFileAtomic(outFile, jsonBytes, 0600); err != nil {
		panic(err)
	}
}

//-------------------------------------------------------------------------------

// FilePVLastSignState stores the mutable part of PrivValidator.
type FilePVLastSignState struct {
	Height    int64  `json:"height"`
	Round     int32  `json:"round"`
	Step      int8   `json:"step"`
	Signature []byte `json:"signature,omitempty"`
	SignBytes []byte `json:"signbytes,omitempty"`

	filePath string
}

// CheckHRS checks the given height, round, step (HRS) against that of the
// FilePVLastSignState. It returns an error if the arguments constitute a regression,
// or if they match but the SignBytes are empty.
// The returned boolean indicates whether the last Signature should be reused -
// it returns true if the HRS matches the arguments and the SignBytes are not empty (indicating
// we have already signed for this HRS, and can reuse the existing signature).
// It panics if the HRS matches the arguments, there's a SignBytes, but no Signature.
func (lss *FilePVLastSignState) CheckHRS(height int64, round int32, step int8) (bool, error) {

	if lss.Height > height {
		return false, fmt.Errorf("height regression. Got %v, last height %v", height, lss.Height)
	}

	if lss.Height == height {
		if lss.Round > round {
			return false, fmt.Errorf("round regression at height %v. Got %v, last round %v", height, round, lss.Round)
		}

		if lss.Round == round {
			if lss.Step > step {
				return false, fmt.Errorf(
					"step regression at height %v round %v. Got %v, last step %v",
					height,
					round,
					step,
					lss.Step,
				)
			} else if lss.Step == step {
				if lss.SignBytes != nil {
					if lss.Signature == nil {
						panic("pv: Signature is nil but SignBytes is not!")
					}
					return true, nil
				}
				return false, errors.New("no SignBytes found")
			}
		}
	}
	return false, nil
}

// Save persists the FilePvLastSignState to its filePath.
func (lss *FilePVLastSignState) Save() {
	outFile := lss.filePath
	if outFile == "" {
		panic("cannot save FilePVLastSignState: filePath not set")
	}
	jsonBytes, err := cometjson.MarshalIndent(lss, "", "  ")
	if err != nil {
		panic(err)
	}
	err = tempfile.WriteFileAtomic(outFile, jsonBytes, 0600)
	if err != nil {
		panic(err)
	}
}

//-------------------------------------------------------------------------------

// FilePV implements PrivValidator using data persisted to disk
// to prevent double signing.
// NOTE: the directories containing pv.Key.filePath and pv.LastSignState.filePath must already exist.
// It includes the LastSignature and LastSignBytes so we don't lose the signature
// if the process crashes after signing but before the resulting consensus message is processed.
type FilePV struct {
	Key           FilePVKey
	LastSignState FilePVLastSignState
}

// NewFilePV generates a new validator from the given key and paths.
func NewFilePV(privKey crypto.PrivKey, keyFilePath, stateFilePath string) *FilePV {
	return &FilePV{
		Key: FilePVKey{
			Address:  privKey.PubKey().Address(),
			PubKey:   privKey.PubKey(),
			PrivKey:  privKey,
			filePath: keyFilePath,
		},
		LastSignState: FilePVLastSignState{
			Step:     0,
			filePath: stateFilePath,
		},
	}
}

// GenFilePV generates a new validator with randomly generated private key
// and sets the filePaths, but does not call Save().
func GenFilePV(keyFilePath, stateFilePath string) *FilePV {
	return NewFilePV(ed25519.GenPrivKey(), keyFilePath, stateFilePath)
}

// If loadState is true, we load from the stateFilePath. Otherwise, we use an empty LastSignState.
func LoadFilePV(keyFilePath, stateFilePath string, loadState bool) (*FilePV, error) {
	keyJSONBytes, err := os.ReadFile(keyFilePath)
	if err != nil {
		return nil, err
	}
	pvKey := FilePVKey{}
	err = cometjson.Unmarshal(keyJSONBytes, &pvKey)
	if err != nil {
		return nil, fmt.Errorf("error reading PrivValidator key from %s: %w", keyFilePath, err)
	}

	// overwrite pubkey and address for convenience
	pvKey.PubKey = pvKey.PrivKey.PubKey()
	pvKey.Address = pvKey.PubKey.Address()
	pvKey.filePath = keyFilePath

	pvState := FilePVLastSignState{}

	if loadState {
		stateJSONBytes, err := os.ReadFile(stateFilePath)
		if err != nil {
			return nil, err
		}
		err = cometjson.Unmarshal(stateJSONBytes, &pvState)
		if err != nil {
			return nil, fmt.Errorf("error reading PrivValidator state from %s: %w", stateFilePath, err)
		}
	}

	pvState.filePath = stateFilePath

	return &FilePV{
		Key:           pvKey,
		LastSignState: pvState,
	}, nil
}

// GetAddress returns the address of the validator.
// Implements PrivValidator.
func (pv *FilePV) GetAddress() types.Address {
	return pv.Key.Address
}

// GetPubKey returns the public key of the validator.
// Implements PrivValidator.
func (pv *FilePV) GetPubKey() (crypto.PubKey, error) {
	return pv.Key.PubKey, nil
}

func (pv *FilePV) Sign(chainID string, block Block) ([]byte, []byte, time.Time, error) {
	height, round, step := block.Height, int32(block.Round), block.Step
	signBytes, voteExtensionSignBytes := block.SignBytes, block.VoteExtensionSignBytes

	lss := pv.LastSignState

	sameHRS, err := lss.CheckHRS(height, round, step)
	if err != nil {
		return nil, nil, block.Timestamp, err
	}

	_, hasVoteExtensions, err := verifySignPayload(chainID, signBytes, voteExtensionSignBytes)
	if err != nil {
		return nil, nil, block.Timestamp, err
	}

	// Vote extensions are non-deterministic, so it is possible that an
	// application may have created a different extension. We therefore always
	// re-sign the vote extensions of precommits. For prevotes and nil
	// precommits, the extension signature will always be empty.
	// Even if the signed over data is empty, we still add the signature
	var extSig []byte
	if hasVoteExtensions {
		extSig, err = pv.Key.PrivKey.Sign(voteExtensionSignBytes)
		if err != nil {
			return nil, nil, block.Timestamp, err
		}
	}

	// We might crash before writing to the wal,
	// causing us to try to re-sign for the same HRS.
	// If signbytes are the same, use the last signature.
	// If they only differ by timestamp, use last timestamp and signature
	// Otherwise, return error
	if sameHRS {
		switch {
		case bytes.Equal(signBytes, lss.SignBytes):
			return lss.Signature, nil, block.Timestamp, nil
		case block.Step == stepPropose:
			if timestamp, ok := checkProposalsOnlyDifferByTimestamp(lss.SignBytes, signBytes); ok {
				return lss.Signature, nil, timestamp, nil
			}
		case block.Step == stepPrevote || block.Step == stepPrecommit:
			if timestamp, ok := checkVotesOnlyDifferByTimestamp(lss.SignBytes, signBytes); ok {
				return lss.Signature, extSig, timestamp, nil
			}
		}

		// If we get here, the votes/proposals differ in more than just timestamp
		// This is the "conflicting data" case that prevents race conditions
		return nil, extSig, block.Timestamp, fmt.Errorf("conflicting data")
	}

	// It passed the checks. Sign the vote
	sig, err := pv.Key.PrivKey.Sign(signBytes)
	if err != nil {
		return nil, nil, block.Timestamp, err
	}
	pv.saveSigned(height, round, step, signBytes, sig)

	return sig, extSig, block.Timestamp, nil
}

// Save persists the FilePV to disk.
func (pv *FilePV) Save() {
	pv.Key.Save()
	pv.LastSignState.Save()
}

// Reset resets all fields in the FilePV.
// NOTE: Unsafe!
func (pv *FilePV) Reset() {
	var sig []byte
	pv.LastSignState.Height = 0
	pv.LastSignState.Round = 0
	pv.LastSignState.Step = 0
	pv.LastSignState.Signature = sig
	pv.LastSignState.SignBytes = nil
	pv.Save()
}

// String returns a string representation of the FilePV.
func (pv *FilePV) String() string {
	return fmt.Sprintf(
		"PrivValidator{%v LH:%v, LR:%v, LS:%v}",
		pv.GetAddress(),
		pv.LastSignState.Height,
		pv.LastSignState.Round,
		pv.LastSignState.Step,
	)
}

// Persist height/round/step and signature
func (pv *FilePV) saveSigned(height int64, round int32, step int8,
	signBytes []byte, sig []byte) {

	pv.LastSignState.Height = height
	pv.LastSignState.Round = round
	pv.LastSignState.Step = step
	pv.LastSignState.Signature = sig
	pv.LastSignState.SignBytes = signBytes
	pv.LastSignState.Save()
}

//-----------------------------------------------------------------------------------------

// returns the timestamp from the lastSignBytes.
// returns true if the only difference in the votes is their timestamp.
func checkVotesOnlyDifferByTimestamp(lastSignBytes, newSignBytes []byte) (time.Time, bool) {
	var lastVote, newVote cometproto.CanonicalVote
	
	// Unmarshal with error handling - return false instead of panic
	if err := protoio.UnmarshalDelimited(lastSignBytes, &lastVote); err != nil {
		// Log the error for debugging but don't panic
		fmt.Printf("WARNING: Failed to unmarshal lastSignBytes as vote: %v\n", err)
		return time.Time{}, false
	}
	if err := protoio.UnmarshalDelimited(newSignBytes, &newVote); err != nil {
		// Log the error for debugging but don't panic
		fmt.Printf("WARNING: Failed to unmarshal newSignBytes as vote: %v\n", err)
		return time.Time{}, false
	}
	
	// Save the timestamp from the last vote before comparison
	lastTime := lastVote.Timestamp
	
	// Manual field-by-field comparison to avoid proto.Equal issues
	// Check Type
	if lastVote.Type != newVote.Type {
		return lastTime, false
	}
	
	// Check Height
	if lastVote.Height != newVote.Height {
		return lastTime, false
	}
	
	// Check Round
	if lastVote.Round != newVote.Round {
		return lastTime, false
	}
	
	// Check ChainID
	if lastVote.ChainID != newVote.ChainID {
		return lastTime, false
	}
	
	// Compare BlockID - handle nil cases carefully
	if (lastVote.BlockID == nil) != (newVote.BlockID == nil) {
		// One is nil, the other is not
		return lastTime, false
	}
	
	if lastVote.BlockID != nil {
		// Both are non-nil, compare the fields
		if !bytes.Equal(lastVote.BlockID.Hash, newVote.BlockID.Hash) {
			return lastTime, false
		}
		
		// Compare PartSetHeader
		if lastVote.BlockID.PartSetHeader.Total != newVote.BlockID.PartSetHeader.Total {
			return lastTime, false
		}
		if !bytes.Equal(lastVote.BlockID.PartSetHeader.Hash, newVote.BlockID.PartSetHeader.Hash) {
			return lastTime, false
		}
	}
	
	// All fields match except (potentially) timestamp
	// This means the votes only differ by timestamp
	return lastTime, true
}

// returns the timestamp from the lastSignBytes.
// returns true if the only difference in the proposals is their timestamp
func checkProposalsOnlyDifferByTimestamp(lastSignBytes, newSignBytes []byte) (time.Time, bool) {
	var lastProposal, newProposal cometproto.CanonicalProposal
	// Unmarshal with error handling - return false instead of panic
	if err := protoio.UnmarshalDelimited(lastSignBytes, &lastProposal); err != nil {
		// Log the error for debugging but don't panic
		fmt.Printf("WARNING: Failed to unmarshal lastSignBytes as proposal: %v\n", err)
		return time.Time{}, false
	}
	if err := protoio.UnmarshalDelimited(newSignBytes, &newProposal); err != nil {
		// Log the error for debugging but don't panic
		fmt.Printf("WARNING: Failed to unmarshal newSignBytes as proposal: %v\n", err)
		return time.Time{}, false
	}

	// Save the timestamp from the last proposal before comparison
	lastTime := lastProposal.Timestamp

	// Manual field-by-field comparison to avoid proto.Equal issues
	// Check Type
	if lastProposal.Type != newProposal.Type {
		return lastTime, false
	}
	// Check Height
	if lastProposal.Height != newProposal.Height {
		return lastTime, false
	}
	// Check Round
	if lastProposal.Round != newProposal.Round {
		return lastTime, false
	}
	// Check POLRound
	if lastProposal.POLRound != newProposal.POLRound {
		return lastTime, false
	}
	// Check ChainID
	if lastProposal.ChainID != newProposal.ChainID {
		return lastTime, false
	}

	// Compare BlockID - handle nil cases carefully
	if (lastProposal.BlockID == nil) != (newProposal.BlockID == nil) {
		// One is nil, the other is not
		return lastTime, false
	}
	
	if lastProposal.BlockID != nil {
		// Both are non-nil, compare the fields
		if !bytes.Equal(lastProposal.BlockID.Hash, newProposal.BlockID.Hash) {
			return lastTime, false
		}
		// Compare PartSetHeader
		if lastProposal.BlockID.PartSetHeader.Total != newProposal.BlockID.PartSetHeader.Total {
			return lastTime, false
		}
		if !bytes.Equal(lastProposal.BlockID.PartSetHeader.Hash, newProposal.BlockID.PartSetHeader.Hash) {
			return lastTime, false
		}
	}
	
	// All fields match except (potentially) timestamp
	// This means the proposals only differ by timestamp
	return lastTime, true
}
