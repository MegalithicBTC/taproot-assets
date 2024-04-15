package tapchannel

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/channeldb"
	lfn "github.com/lightningnetwork/lnd/fn"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/tlv"
)

const (
	// DefaultTimeout is the default timeout we use for RPC and database
	// operations.
	DefaultTimeout = 30 * time.Second
)

// LeafCreatorConfig defines the configuration for the auxiliary leaf creator.
type LeafCreatorConfig struct {
	ChainParams *address.ChainParams
}

// AuxLeafCreator is a Taproot Asset auxiliary leaf creator that can be used to
// create auxiliary leaves for Taproot Asset channels.
type AuxLeafCreator struct {
	startOnce sync.Once
	stopOnce  sync.Once

	cfg *LeafCreatorConfig

	// ContextGuard provides a wait group and main quit channel that can be
	// used to create guarded contexts.
	*fn.ContextGuard
}

// NewAuxLeafCreator creates a new Taproot Asset auxiliary leaf creator based on
// the passed config.
func NewAuxLeafCreator(cfg *LeafCreatorConfig) *AuxLeafCreator {
	return &AuxLeafCreator{
		cfg: cfg,
		ContextGuard: &fn.ContextGuard{
			DefaultTimeout: DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}
}

// Start attempts to start a new aux leaf creator.
func (c *AuxLeafCreator) Start() error {
	var startErr error
	c.startOnce.Do(func() {
		log.Info("Starting aux leaf creator")
	})
	return startErr
}

// Stop signals for a custodian to gracefully exit.
func (c *AuxLeafCreator) Stop() error {
	var stopErr error
	c.stopOnce.Do(func() {
		log.Info("Stopping aux leaf creator")

		close(c.Quit)
		c.Wg.Wait()
	})

	return stopErr
}

// A compile-time check to ensure that AuxLeafCreator fully implements the
// lnwallet.AuxLeafStore interface.
var _ lnwallet.AuxLeafStore = (*AuxLeafCreator)(nil)

// FetchLeavesFromView attempts to fetch the auxiliary leaves that correspond to
// the passed aux blob, and pending fully evaluated HTLC view.
func (c *AuxLeafCreator) FetchLeavesFromView(chanState *channeldb.OpenChannel,
	prevBlob tlv.Blob, originalView *lnwallet.HtlcView, isOurCommit bool,
	ourBalance, theirBalance lnwire.MilliSatoshi,
	keys lnwallet.CommitmentKeyRing) (lfn.Option[lnwallet.CommitAuxLeaves],
	lnwallet.CommitSortFunc, error) {

	none := lfn.None[lnwallet.CommitAuxLeaves]()

	if chanState.CustomBlob.IsNone() {
		return none, nil, fmt.Errorf("channel has no custom blob")
	}

	chanAssetState, err := DecodeOpenChannel(
		chanState.CustomBlob.UnsafeFromSome(),
	)
	if err != nil {
		return none, nil, fmt.Errorf("unable to decode channel asset "+
			"state: %w", err)
	}

	prevState, err := DecodeCommitment(prevBlob)
	if err != nil {
		return none, nil, fmt.Errorf("unable to decode prev commit "+
			"state: %w", err)
	}

	allocations, newCommitment, err := c.generateAllocations(
		prevState, chanState, chanAssetState, isOurCommit, ourBalance,
		theirBalance, originalView, keys,
	)
	if err != nil {
		return none, nil, fmt.Errorf("unable to generate allocations: "+
			"%w", err)
	}

	customCommitSort := func(tx *wire.MsgTx, uint32s []uint32) error {
		return InPlaceCustomCommitSort(tx, uint32s, allocations)
	}

	return lfn.Some(newCommitment.Leaves()), customCommitSort, nil
}

// FetchLeavesFromCommit attempts to fetch the auxiliary leaves that correspond
// to the passed aux blob, and an existing channel commitment.
func (c *AuxLeafCreator) FetchLeavesFromCommit(chanState *channeldb.OpenChannel,
	com channeldb.ChannelCommitment,
	keys lnwallet.CommitmentKeyRing) (lfn.Option[lnwallet.CommitAuxLeaves],
	error) {

	none := lfn.None[lnwallet.CommitAuxLeaves]()

	if com.CustomBlob.IsNone() {
		return none, fmt.Errorf("commitment has no custom blob")
	}

	commitment, err := DecodeCommitment(com.CustomBlob.UnsafeFromSome())
	if err != nil {
		return none, fmt.Errorf("unable to decode commitment: %w", err)
	}

	incomingHtlcs := commitment.IncomingHtlcAssets.Val.htlcOutputs
	incomingHtlcLeaves := commitment.AuxLeaves.Val.IncomingHtlcLeaves.
		Val.htlcAuxLeaves
	outgoingHtlcs := commitment.OutgoingHtlcAssets.Val.htlcOutputs
	outgoingHtlcLeaves := commitment.AuxLeaves.Val.
		OutgoingHtlcLeaves.Val.htlcAuxLeaves
	for idx := range com.Htlcs {
		htlc := com.Htlcs[idx]
		htlcIdx := htlc.HtlcIndex

		if htlc.Incoming {
			htlcOutputs := incomingHtlcs[htlcIdx].outputs
			auxLeaf := incomingHtlcLeaves[htlcIdx].AuxLeaf
			leaf, err := CreateSecondLevelHtlcTx(
				chanState, com.CommitTx, htlc.Amt.ToSatoshis(),
				keys, c.cfg.ChainParams, htlcOutputs,
			)
			if err != nil {
				return none, fmt.Errorf("unable to create "+
					"second level HTLC leaf: %w", err)
			}

			existingLeaf := lfn.MapOption(
				func(l tapLeafRecord) txscript.TapLeaf {
					return l.leaf
				},
			)(auxLeaf.ValOpt())

			incomingHtlcLeaves[htlcIdx] = NewHtlcAuxLeaf(
				input.HtlcAuxLeaf{
					AuxTapLeaf:      existingLeaf,
					SecondLevelLeaf: leaf,
				},
			)
		} else {
			htlcOutputs := outgoingHtlcs[htlcIdx].outputs
			auxLeaf := outgoingHtlcLeaves[htlcIdx].AuxLeaf
			leaf, err := CreateSecondLevelHtlcTx(
				chanState, com.CommitTx, htlc.Amt.ToSatoshis(),
				keys, c.cfg.ChainParams, htlcOutputs,
			)
			if err != nil {
				return none, fmt.Errorf("unable to create "+
					"second level HTLC leaf: %w", err)
			}

			existingLeaf := lfn.MapOption(
				func(l tapLeafRecord) txscript.TapLeaf {
					return l.leaf
				},
			)(auxLeaf.ValOpt())

			outgoingHtlcLeaves[htlcIdx] = NewHtlcAuxLeaf(
				input.HtlcAuxLeaf{
					AuxTapLeaf:      existingLeaf,
					SecondLevelLeaf: leaf,
				},
			)
		}
	}

	return lfn.Some(commitment.Leaves()), nil
}

// FetchLeavesFromRevocation attempts to fetch the auxiliary leaves
// from a channel revocation that stores balance + blob information.
func (c *AuxLeafCreator) FetchLeavesFromRevocation(
	rev *channeldb.RevocationLog) (lfn.Option[lnwallet.CommitAuxLeaves],
	error) {

	none := lfn.None[lnwallet.CommitAuxLeaves]()

	if rev.CustomBlob.ValOpt().IsNone() {
		return none, fmt.Errorf("revocation has no custom blob")
	}

	commitment, err := DecodeCommitment(
		rev.CustomBlob.ValOpt().UnsafeFromSome(),
	)
	if err != nil {
		return none, fmt.Errorf("unable to decode commitment: %w", err)
	}

	return lfn.Some(commitment.Leaves()), nil
}

// ApplyHtlcView serves as the state transition function for the custom
// channel's blob. Given the old blob, and an HTLC view, then a new
// blob should be returned that reflects the pending updates.
func (c *AuxLeafCreator) ApplyHtlcView(chanState *channeldb.OpenChannel,
	prevBlob tlv.Blob, originalView *lnwallet.HtlcView, isOurCommit bool,
	ourBalance, theirBalance lnwire.MilliSatoshi,
	keys lnwallet.CommitmentKeyRing) (lfn.Option[tlv.Blob], error) {

	none := lfn.None[tlv.Blob]()

	if chanState.CustomBlob.IsNone() {
		return none, fmt.Errorf("channel has no custom blob")
	}

	chanAssetState, err := DecodeOpenChannel(
		chanState.CustomBlob.UnsafeFromSome(),
	)
	if err != nil {
		return none, fmt.Errorf("unable to decode channel asset "+
			"state: %w", err)
	}

	prevState, err := DecodeCommitment(prevBlob)
	if err != nil {
		return none, fmt.Errorf("unable to decode prev commit state: "+
			"%w", err)
	}

	_, newCommitment, err := c.generateAllocations(
		prevState, chanState, chanAssetState, isOurCommit, ourBalance,
		theirBalance, originalView, keys,
	)
	if err != nil {
		return none, fmt.Errorf("unable to generate allocations: %w",
			err)
	}

	var buf bytes.Buffer
	err = newCommitment.Encode(&buf)
	if err != nil {
		return none, fmt.Errorf("unable to encode commitment: %w", err)
	}

	return lfn.Some(buf.Bytes()), nil
}

// generateAllocations generates allocations for a channel commitment.
func (c *AuxLeafCreator) generateAllocations(prevState *Commitment,
	chanState *channeldb.OpenChannel, chanAssetState *OpenChannel,
	isOurCommit bool, ourBalance, theirBalance lnwire.MilliSatoshi,
	originalView *lnwallet.HtlcView,
	keys lnwallet.CommitmentKeyRing) ([]*Allocation, *Commitment, error) {

	// Process all HTLCs in the view to compute the new asset balance.
	ourAssetBalance, theirAssetBalance, filteredView, err := ComputeView(
		prevState.LocalAssets.Val.Sum(),
		prevState.RemoteAssets.Val.Sum(), isOurCommit, originalView,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to compute view: %w", err)
	}

	dustLimit := chanState.LocalChanCfg.DustLimit
	if !isOurCommit {
		dustLimit = chanState.RemoteChanCfg.DustLimit
	}

	// Make sure that every output that carries an asset balance has a
	// corresponding non-dust BTC output.
	wantLocalAnchor, wantRemoteAnchor, err := SanityCheckAmounts(
		ourBalance.ToSatoshis(), theirBalance.ToSatoshis(),
		ourAssetBalance, theirAssetBalance, filteredView,
		chanState.ChanType, isOurCommit, dustLimit,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("error checking amounts: %w", err)
	}

	// With all the balances checked, we can now create allocation entries
	// for each on-chain output. An allocation is a helper struct to keep
	// track of the original on-chain output, the keys/scripts involved on
	// the BTC level as well as the asset UTXOs that are being distributed.
	allocations, err := CreateAllocations(
		chanState, ourBalance.ToSatoshis(), theirBalance.ToSatoshis(),
		ourAssetBalance, theirAssetBalance, wantLocalAnchor,
		wantRemoteAnchor, filteredView, isOurCommit, keys,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create allocations: %w",
			err)
	}

	inputProofs := fn.Map(
		chanAssetState.Assets(), func(o *AssetOutput) *proof.Proof {
			return &o.Proof.Val
		},
	)

	// Now we can distribute the inputs according to the allocations. This
	// creates a virtual packet for each distinct asset ID that is committed
	// to the channel.
	vPackets, err := DistributeCoins(
		inputProofs, allocations, c.cfg.ChainParams,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to distribute coins: %w",
			err)
	}

	// Prepare the output assets for each virtual packet, then create the
	// output commitments.
	ctx := context.Background()
	for idx := range vPackets {
		err := tapsend.PrepareOutputAssets(ctx, vPackets[idx])
		if err != nil {
			return nil, nil, fmt.Errorf("unable to prepare output "+
				"assets: %w", err)
		}
	}

	outCommitments, err := tapsend.CreateOutputCommitments(vPackets)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create output "+
			"commitments: %w", err)
	}

	// The output commitment is all we need to create the auxiliary leaves.
	// We map the output commitments (which are keyed by on-chain output
	// index) back to the allocation.
	err = AssignOutputCommitments(allocations, outCommitments)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to assign output "+
			"commitments: %w", err)
	}

	// Now we have all the information we need to create the asset proofs.
	for idx := range vPackets {
		vPkt := vPackets[idx]
		for outIdx := range vPkt.Outputs {
			proofSuffix, err := tapsend.CreateProofSuffixCustom(
				nil, vPkt, outCommitments, outIdx, vPackets,
				ExclusionProofsFromAllocations(allocations),
			)
			if err != nil {
				return nil, nil, fmt.Errorf("unable to create "+
					"proof suffix for output %d: %w",
					outIdx, err)
			}

			vPkt.Outputs[outIdx].ProofSuffix = proofSuffix
		}
	}

	// Next, we can convert the allocations to auxiliary leaves and from
	// those construct our Commitment struct that will in the end also hold
	// our proof suffixes.
	newCommitment, err := ToCommitment(allocations, vPackets)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to convert to commitment: "+
			"%w", err)
	}

	return allocations, newCommitment, nil
}
