package signer

import (
	"context"
	"time"

	cometlog "github.com/cometbft/cometbft/libs/log"
)

// SignAndTrack signs a block and tracks metrics
func SignAndTrack(
	ctx context.Context,
	logger cometlog.Logger,
	validator PrivValidator,
	chainID string,
	block Block,
) ([]byte, []byte, time.Time, error) {
	sig, voteExtSig, timestamp, err := validator.Sign(ctx, chainID, block)
	if err != nil {
		switch typedErr := err.(type) {
		case *BeyondBlockError:
			logger.Debug(
				"Rejecting sign request",
				"type", signType(block.Step),
				"chain_id", chainID,
				"height", block.Height,
				"round", block.Round,
				"reason", typedErr.msg,
			)
			beyondBlockErrors.WithLabelValues(chainID).Inc()
		default:
			logger.Error(
				"Failed to sign",
				"type", signType(block.Step),
				"chain_id", chainID,
				"height", block.Height,
				"round", block.Round,
				"error", err,
			)
			failedSignVote.WithLabelValues(chainID).Inc()
		}
		return nil, nil, time.Time{}, err
	}
	logger.Info(
		"Signed",
		"type", signType(block.Step),
		"chain_id", chainID,
		"height", block.Height,
		"round", block.Round,
		"attempt", block.Timestamp,
	)

	switch block.Step {
	case stepPropose:
		lastProposalHeight.WithLabelValues(chainID).Set(float64(block.Height))
		totalProposalsSigned.WithLabelValues(chainID).Inc()
	case stepPrevote:
		lastPrevoteHeight.WithLabelValues(chainID).Set(float64(block.Height))
		totalPrevotesSigned.WithLabelValues(chainID).Inc()
	case stepPrecommit:
		lastPrecommitHeight.WithLabelValues(chainID).Set(float64(block.Height))
		totalPrecommitsSigned.WithLabelValues(chainID).Inc()
	}

	return sig, voteExtSig, timestamp, nil
}