package tapchannel

import (
	"bytes"
	"context"
	"fmt"
	"sort"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/channeldb"
	lfn "github.com/lightningnetwork/lnd/fn"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/lightningnetwork/lnd/tlv"
)

// DecodedDescriptor is a wrapper around a PaymentDescriptor that also includes
// the decoded asset balances of the HTLC to avoid multiple decoding round
// trips.
type DecodedDescriptor struct {
	// PaymentDescriptor is the original payment descriptor.
	*lnwallet.PaymentDescriptor

	// AssetBalances is the decoded asset balances of the HTLC.
	AssetBalances []*AssetBalance
}

// DecodedView is a copy of the original HTLC view, but with the asset balances
// of the HTLCs decoded.
type DecodedView struct {
	// OurUpdates is a list of decoded descriptors for our updates.
	OurUpdates []*DecodedDescriptor

	// TheirUpdates is a list of decoded descriptors for their updates.
	TheirUpdates []*DecodedDescriptor

	// FeePerKw is the current commitment fee rate.
	FeePerKw chainfee.SatPerKWeight
}

// ComputeView processes all update entries in both HTLC update logs,
// producing a final view which is the result of properly applying all adds,
// settles, timeouts and fee updates found in both logs. The resulting view
// returned reflects the current state of HTLCs within the remote or local
// commitment chain, and the current commitment fee rate.
func ComputeView(ourBalance, theirBalance uint64, isOurCommit bool,
	original *lnwallet.HtlcView) (uint64, uint64, *DecodedView, error) {

	newView := &DecodedView{
		FeePerKw: original.FeePerKw,
	}

	// We use two maps, one for the local log and one for the remote log to
	// keep track of which entries we need to skip when creating the final
	// htlc view. We skip an entry whenever we find a settle or a timeout
	// modifying an entry.
	skipUs := make(map[uint64]struct{})
	skipThem := make(map[uint64]struct{})

	local, remote := ourBalance, theirBalance
	for _, entry := range original.OurUpdates {
		// Skip any entries that aren't TAP related.
		if entry.CustomRecords.IsNone() {
			continue
		}

		switch entry.EntryType {
		// Skip adds for now, they will be processed below.
		case lnwallet.Add:
			continue

		// Fee updates don't concern us at the asset level.
		case lnwallet.FeeUpdate:
			continue

		// A settle or a timeout means we need to skip the corresponding
		// "add" entry.
		case lnwallet.Settle, lnwallet.Fail, lnwallet.MalformedFail:
			skipUs[entry.ParentIndex] = struct{}{}

			var err error
			entry.CustomRecords.WhenSome(func(blob tlv.Blob) {
				var assetHtlc *Htlc
				assetHtlc, err = DecodeHtlc(blob)
				if err != nil {
					err = fmt.Errorf("unable to decode "+
						"asset htlc: %w", err)
					return
				}

				decodedEntry := &DecodedDescriptor{
					PaymentDescriptor: entry,
					AssetBalances:     assetHtlc.Balances(),
				}

				local, remote = processRemoveEntry(
					decodedEntry, local, remote,
					isOurCommit, true,
				)
			})
			if err != nil {
				return 0, 0, nil, fmt.Errorf("error "+
					"processing our remove entry: %w", err)
			}
		}
	}
	for _, entry := range original.TheirUpdates {
		// Skip any entries that aren't TAP related.
		if entry.CustomRecords.IsNone() {
			continue
		}

		switch entry.EntryType {
		// Skip adds for now, they will be processed below.
		case lnwallet.Add:
			continue

		// Fee updates don't concern us at the asset level.
		case lnwallet.FeeUpdate:
			continue

		// A settle or a timeout means we need to skip the corresponding
		// "add" entry.
		case lnwallet.Settle, lnwallet.Fail, lnwallet.MalformedFail:
			skipUs[entry.ParentIndex] = struct{}{}

			var err error
			entry.CustomRecords.WhenSome(func(blob tlv.Blob) {
				var assetHtlc *Htlc
				assetHtlc, err = DecodeHtlc(blob)
				if err != nil {
					err = fmt.Errorf("unable to decode "+
						"asset htlc: %w", err)
					return
				}

				decodedEntry := &DecodedDescriptor{
					PaymentDescriptor: entry,
					AssetBalances:     assetHtlc.Balances(),
				}
				local, remote = processRemoveEntry(
					decodedEntry, local, remote,
					isOurCommit, false,
				)
			})
			if err != nil {
				return 0, 0, nil, fmt.Errorf("error "+
					"processing their remove entry: %w",
					err)
			}
		}
	}

	// Next we take a second pass through all the log entries, skipping any
	// settled HTLCs, and debiting the chain state balance due to any newly
	// added HTLCs.
	for _, entry := range original.OurUpdates {
		isAdd := entry.EntryType == lnwallet.Add

		// Skip any entries that aren't adds or adds that were already
		// settled or failed by a child HTLC entry we processed above.
		if _, ok := skipUs[entry.HtlcIndex]; !isAdd || ok {
			continue
		}

		// Again skip any entries that aren't TAP related.
		if entry.CustomRecords.IsNone() {
			continue
		}

		var err error
		entry.CustomRecords.WhenSome(func(blob tlv.Blob) {
			var assetHtlc *Htlc
			assetHtlc, err = DecodeHtlc(blob)
			if err != nil {
				err = fmt.Errorf("unable to decode asset "+
					"htlc: %w", err)
				return
			}

			decodedEntry := &DecodedDescriptor{
				PaymentDescriptor: entry,
				AssetBalances:     assetHtlc.Balances(),
			}
			local, remote = processAddEntry(
				decodedEntry, local, remote, isOurCommit, false,
			)

			newView.OurUpdates = append(
				newView.OurUpdates, decodedEntry,
			)
		})
		if err != nil {
			return 0, 0, nil, fmt.Errorf("error processing our "+
				"add entry: %w", err)
		}
	}
	for _, entry := range original.TheirUpdates {
		isAdd := entry.EntryType == lnwallet.Add

		// Skip any entries that aren't adds or adds that were already
		// settled or failed by a child HTLC entry we processed above.
		if _, ok := skipThem[entry.HtlcIndex]; !isAdd || ok {
			continue
		}

		// Again skip any entries that aren't TAP related.
		if entry.CustomRecords.IsNone() {
			continue
		}

		var err error
		entry.CustomRecords.WhenSome(func(blob tlv.Blob) {
			var assetHtlc *Htlc
			assetHtlc, err = DecodeHtlc(blob)
			if err != nil {
				err = fmt.Errorf("unable to decode asset "+
					"htlc: %w", err)
				return
			}

			decodedEntry := &DecodedDescriptor{
				PaymentDescriptor: entry,
				AssetBalances:     assetHtlc.Balances(),
			}
			local, remote = processAddEntry(
				decodedEntry, local, remote, isOurCommit, true,
			)

			newView.TheirUpdates = append(
				newView.TheirUpdates, decodedEntry,
			)
		})
		if err != nil {
			return 0, 0, nil, fmt.Errorf("error processing their "+
				"add entry: %w", err)
		}
	}

	return local, remote, newView, nil
}

// processRemoveEntry processes the removal of an HTLC from the commitment
// transaction. It returns the updated balances for both parties.
func processRemoveEntry(htlc *DecodedDescriptor, ourBalance,
	theirBalance uint64, isOurCommit, isIncoming bool) (uint64, uint64) {

	// Ignore any removal entries which have already been processed.
	removeHeight := lnwallet.RemoveHeight(
		htlc.PaymentDescriptor, !isOurCommit,
	)
	if *removeHeight != 0 {
		return ourBalance, theirBalance
	}

	var (
		amount = Sum(htlc.AssetBalances)
		isFail = htlc.EntryType == lnwallet.Fail ||
			htlc.EntryType == lnwallet.MalformedFail
	)
	switch {
	// If an incoming HTLC is being settled, then this means that we've
	// received the preimage either from another subsystem, or the upstream
	// peer in the route. Therefore, we increase our balance by the HTLC
	// amount.
	case isIncoming && htlc.EntryType == lnwallet.Settle:
		ourBalance += amount

	// Otherwise, this HTLC is being failed out, therefore the value of the
	// HTLC should return to the remote party.
	case isIncoming && isFail:
		theirBalance += amount

	// If an outgoing HTLC is being settled, then this means that the
	// downstream party resented the preimage or learned of it via a
	// downstream peer. In either case, we credit their settled value with
	// the value of the HTLC.
	case !isIncoming && htlc.EntryType == lnwallet.Settle:
		theirBalance += amount

	// Otherwise, one of our outgoing HTLCs has timed out, so the value of
	// the HTLC should be returned to our settled balance.
	case !isIncoming && isFail:
		ourBalance += amount
	}

	return ourBalance, theirBalance
}

// processAddEntry processes the addition of an HTLC to the commitment
// transaction. It returns the updated balances for both parties.
func processAddEntry(htlc *DecodedDescriptor, ourBalance, theirBalance uint64,
	isOurCommit, isIncoming bool) (uint64, uint64) {

	// Ignore any add entries which have already been processed.
	addHeight := lnwallet.AddHeight(htlc.PaymentDescriptor, !isOurCommit)
	if *addHeight != 0 {
		return ourBalance, theirBalance
	}

	var amount = Sum(htlc.AssetBalances)
	if isIncoming {
		// If this is a new incoming (un-committed) HTLC, then we need
		// to update their balance accordingly by subtracting the
		// amount of the HTLC that are funds pending.
		theirBalance -= amount
	} else {
		// Similarly, we need to debit our balance if this is an
		// outgoing HTLC to reflect the pending balance.
		ourBalance -= amount
	}

	return ourBalance, theirBalance
}

// SanityCheckAmounts makes sure that any output that carries an asset has a
// non-dust satoshi balance. It also checks and returns whether we need a local
// and/or remote anchor output.
func SanityCheckAmounts(ourBalance, theirBalance btcutil.Amount,
	ourAssetBalance, theirAssetBalance uint64, view *DecodedView,
	chanType channeldb.ChannelType, isOurs bool,
	dustLimit btcutil.Amount) (bool, bool, error) {

	var (
		numHTLCs int64
		feePerKw = view.FeePerKw
	)
	for _, entry := range view.OurUpdates {
		isDust := lnwallet.HtlcIsDust(
			chanType, false, isOurs, feePerKw,
			entry.Amount.ToSatoshis(), dustLimit,
		)
		if Sum(entry.AssetBalances) > 0 && isDust {
			return false, false, fmt.Errorf("outgoing HTLC asset "+
				"balance %d has dust BTC balance (%v) on HTLC "+
				"with index %d", ourAssetBalance, ourBalance,
				entry.HtlcIndex)
		}

		numHTLCs++
	}
	for _, entry := range view.TheirUpdates {
		isDust := lnwallet.HtlcIsDust(
			chanType, true, isOurs, feePerKw,
			entry.Amount.ToSatoshis(), dustLimit,
		)
		if Sum(entry.AssetBalances) > 0 && isDust {
			return false, false, fmt.Errorf("incoming HTLC asset "+
				"balance %d has dust BTC balance (%v) on HTLC "+
				"with index %d", ourAssetBalance, ourBalance,
				entry.HtlcIndex)
		}

		numHTLCs++
	}

	// Any output that carries an asset balance must have a corresponding
	// non-dust satoshi balance.
	if ourAssetBalance > 0 && ourBalance < dustLimit {
		return false, false, fmt.Errorf("our asset balance %d has "+
			"dust BTC balance (%v)", ourAssetBalance, ourBalance)
	}
	if theirAssetBalance > 0 && theirBalance < dustLimit {
		return false, false, fmt.Errorf("their asset balance %d has "+
			"dust BTC balance (%v)", theirAssetBalance,
			theirBalance)
	}

	// If for some reason the channel type doesn't have anchors, we fail
	// here, as this is a requirement for TAP channels.
	if !chanType.HasAnchors() {
		return false, false, fmt.Errorf("channel type %v doesn't have "+
			"anchors", chanType)
	}

	wantLocalAnchor := ourAssetBalance > 0 || numHTLCs > 0
	wantRemoteAnchor := theirAssetBalance > 0 || numHTLCs > 0

	return wantLocalAnchor, wantRemoteAnchor, nil
}

// CreateAllocations creates the allocations for the channel state.
func CreateAllocations(chanState *channeldb.OpenChannel, ourBalance,
	theirBalance btcutil.Amount, ourAssetBalance, theirAssetBalance uint64,
	wantLocalCommitAnchor, wantRemoteCommitAnchor bool,
	filteredView *DecodedView, isOurCommit bool,
	keys lnwallet.CommitmentKeyRing) ([]*Allocation, error) {

	// We'll have at most 2 outputs for the local and remote commitment
	// anchor outputs, 2 outputs for the local/remote balance and one output
	// for each HTLC. We might over-allocate slightly, but that's likely
	// slightly better than re-allocating in this case.
	var (
		numAllocations = len(filteredView.OurUpdates) +
			len(filteredView.TheirUpdates) + 4
		allocations = make([]*Allocation, 0, numAllocations)
		addAlloc    = func(a *Allocation) {
			allocations = append(allocations, a)
		}
	)

	var leaseExpiry uint32
	if chanState.ChanType.HasLeaseExpiration() {
		leaseExpiry = chanState.ThawHeight
	}

	var err error
	if isOurCommit {
		err = addCommitmentOutputs(
			chanState.ChanType, &chanState.LocalChanCfg,
			&chanState.RemoteChanCfg, chanState.IsInitiator,
			ourBalance, theirBalance, ourAssetBalance,
			theirAssetBalance, wantLocalCommitAnchor,
			wantRemoteCommitAnchor, keys, leaseExpiry, addAlloc,
		)
	} else {
		err = addCommitmentOutputs(
			chanState.ChanType, &chanState.RemoteChanCfg,
			&chanState.LocalChanCfg, !chanState.IsInitiator,
			theirBalance, ourBalance, theirAssetBalance,
			ourAssetBalance, wantRemoteCommitAnchor,
			wantLocalCommitAnchor, keys, leaseExpiry, addAlloc,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("error creating commitment output "+
			"allocations: %w", err)
	}

	// Finally, we add the HTLC outputs, using this helper function to
	// distinguish between incoming and outgoing HTLCs.
	addHtlc := func(htlc *DecodedDescriptor, isIncoming bool) error {
		htlcScript, err := lnwallet.GenTaprootHtlcScript(
			isIncoming, isOurCommit, htlc.Timeout, htlc.RHash,
			&keys, lfn.None[txscript.TapLeaf](),
		)
		if err != nil {
			return fmt.Errorf("error creating HTLC script: %w", err)
		}

		sibling, htlcTree, err := LeavesFromTapscriptScriptTree(
			htlcScript,
		)
		if err != nil {
			return fmt.Errorf("error creating HTLC script "+
				"sibling: %w", err)
		}

		allocType := CommitAllocationHtlcOutgoing
		if isIncoming {
			allocType = CommitAllocationHtlcIncoming
		}

		allocations = append(allocations, &Allocation{
			Type:           allocType,
			Amount:         Sum(htlc.AssetBalances),
			AssetVersion:   asset.V1,
			BtcAmount:      htlc.Amount.ToSatoshis(),
			InternalKey:    htlcTree.InternalKey,
			NonAssetLeaves: sibling,
			ScriptKey: asset.NewScriptKey(
				htlcTree.TaprootKey,
			),
			SortPkScript: schnorr.SerializePubKey(
				htlcTree.TaprootKey,
			),
			CLTV:      htlc.Timeout,
			HtlcIndex: htlc.HtlcIndex,
		})

		return nil
	}
	for _, htlc := range filteredView.OurUpdates {
		err := addHtlc(htlc, false)
		if err != nil {
			return nil, fmt.Errorf("error creating our HTLC "+
				"allocation: %w", err)
		}
	}

	for _, htlc := range filteredView.TheirUpdates {
		err := addHtlc(htlc, true)
		if err != nil {
			return nil, fmt.Errorf("error creating their HTLC "+
				"allocation: %w", err)
		}
	}

	// With all allocations created, we now sort them to ensure that we have
	// a stable and deterministic order that both parties can arrive at. We
	// then assign the output indexes according to that order.
	InPlaceAllocationSort(allocations)
	for idx := range allocations {
		allocations[idx].OutputIndex = uint32(idx)
	}

	return allocations, nil
}

// addCommitmentOutputs creates the allocations for all commitment and
// commitment anchor outputs, depending on whether this is our commitment
// transaction or not.
func addCommitmentOutputs(chanType channeldb.ChannelType, localChanCfg,
	remoteChanCfg *channeldb.ChannelConfig, initiator bool, ourBalance,
	theirBalance btcutil.Amount, ourAssetBalance, theirAssetBalance uint64,
	wantLocalCommitAnchor, wantRemoteCommitAnchor bool,
	keys lnwallet.CommitmentKeyRing, leaseExpiry uint32,
	addAllocation func(a *Allocation)) error {

	// Start with the commitment anchor outputs.
	localAnchor, remoteAnchor, err := lnwallet.CommitScriptAnchors(
		chanType, localChanCfg, remoteChanCfg, &keys,
	)
	if err != nil {
		return fmt.Errorf("error creating commitment anchors: %w", err)
	}

	if wantLocalCommitAnchor {
		sibling, scriptTree, err := LeavesFromTapscriptScriptTree(
			localAnchor,
		)
		if err != nil {
			return fmt.Errorf("error creating local anchor script "+
				"sibling: %w", err)
		}

		addAllocation(&Allocation{
			// Commitment anchor outputs never carry assets.
			Type:           AllocationTypeNoAssets,
			Amount:         0,
			BtcAmount:      lnwallet.AnchorSize,
			InternalKey:    scriptTree.InternalKey,
			NonAssetLeaves: sibling,
			SortPkScript: schnorr.SerializePubKey(
				scriptTree.TaprootKey,
			),
		})
	}
	if wantRemoteCommitAnchor {
		sibling, scriptTree, err := LeavesFromTapscriptScriptTree(
			remoteAnchor,
		)
		if err != nil {
			return fmt.Errorf("error creating remote anchor "+
				"script sibling: %w", err)
		}

		addAllocation(&Allocation{
			// Commitment anchor outputs never carry assets.
			Type:           AllocationTypeNoAssets,
			Amount:         0,
			BtcAmount:      lnwallet.AnchorSize,
			InternalKey:    scriptTree.InternalKey,
			NonAssetLeaves: sibling,
			SortPkScript: schnorr.SerializePubKey(
				scriptTree.TaprootKey,
			),
		})
	}

	// We've asserted that we have a non-dust BTC balance if we have an
	// asset balance before, so we can just check the asset balance here.
	if ourAssetBalance > 0 {
		toLocalScript, err := lnwallet.CommitScriptToSelf(
			chanType, initiator, keys.ToLocalKey,
			keys.RevocationKey, uint32(localChanCfg.CsvDelay),
			leaseExpiry, lfn.None[txscript.TapLeaf](),
		)
		if err != nil {
			return fmt.Errorf("error creating to local script: %w",
				err)
		}

		sibling, toLocalTree, err := LeavesFromTapscriptScriptTree(
			toLocalScript,
		)
		if err != nil {
			return fmt.Errorf("error creating to local script "+
				"sibling: %w", err)
		}

		addAllocation(&Allocation{
			Type:           CommitAllocationToLocal,
			Amount:         ourAssetBalance,
			AssetVersion:   asset.V1,
			SplitRoot:      initiator,
			BtcAmount:      ourBalance,
			InternalKey:    toLocalTree.InternalKey,
			NonAssetLeaves: sibling,
			ScriptKey: asset.NewScriptKey(
				toLocalTree.TaprootKey,
			),
			SortPkScript: schnorr.SerializePubKey(
				toLocalTree.TaprootKey,
			),
		})
	}

	if theirAssetBalance > 0 {
		toRemoteScript, _, err := lnwallet.CommitScriptToRemote(
			chanType, initiator, keys.ToRemoteKey, leaseExpiry,
			lfn.None[txscript.TapLeaf](),
		)
		if err != nil {
			return fmt.Errorf("error creating to remote script: %w",
				err)
		}

		sibling, toRemoteTree, err := LeavesFromTapscriptScriptTree(
			toRemoteScript,
		)
		if err != nil {
			return fmt.Errorf("error creating to remote script "+
				"sibling: %w", err)
		}

		addAllocation(&Allocation{
			Type:           CommitAllocationToRemote,
			Amount:         theirAssetBalance,
			AssetVersion:   asset.V1,
			SplitRoot:      !initiator,
			BtcAmount:      theirBalance,
			InternalKey:    toRemoteTree.InternalKey,
			NonAssetLeaves: sibling,
			ScriptKey: asset.NewScriptKey(
				toRemoteTree.TaprootKey,
			),
			SortPkScript: schnorr.SerializePubKey(
				toRemoteTree.TaprootKey,
			),
		})
	}

	return nil
}

// LeavesFromTapscriptScriptTree creates a tapscript sibling from a commit
// script tree.
func LeavesFromTapscriptScriptTree(
	scriptTree input.ScriptDescriptor) ([]txscript.TapLeaf,
	input.ScriptTree, error) {

	emptyTree := input.ScriptTree{}

	tapscriptTree, ok := scriptTree.(input.TapscriptDescriptor)
	if !ok {
		return nil, emptyTree, fmt.Errorf("expected tapscript tree, "+
			"got %T", scriptTree)
	}

	leaves := fn.Map(
		tapscriptTree.TapScriptTree().LeafMerkleProofs,
		func(proof txscript.TapscriptProof) txscript.TapLeaf {
			return proof.TapLeaf
		},
	)

	return leaves, tapscriptTree.Tree(), nil
}

// ToCommitment converts the allocations to a Commitment struct.
func ToCommitment(allocations []*Allocation,
	vPackets []*tappsbt.VPacket) (*Commitment, error) {

	var (
		localAssets   []*AssetOutput
		remoteAssets  []*AssetOutput
		outgoingHtlcs = make(map[input.HtlcIndex][]*AssetOutput)
		incomingHtlcs = make(map[input.HtlcIndex][]*AssetOutput)
		auxLeaves     lnwallet.CommitAuxLeaves
	)

	// Start with the to_local output. There should be at most one of these
	// outputs.
	toLocal := fn.Filter(allocations, FilterByType(CommitAllocationToLocal))
	switch {
	case len(toLocal) > 1:
		return nil, fmt.Errorf("expected at most one to local output, "+
			"got %d", len(toLocal))

	case len(toLocal) == 1:
		toLocalLeaf, err := toLocal[0].AuxLeaf()
		if err != nil {
			return nil, fmt.Errorf("error creating to local aux "+
				"leaf: %w", err)
		}
		auxLeaves.LocalAuxLeaf = lfn.Some(toLocalLeaf)

		localAssets, err = collectOutputs(toLocal[0], vPackets)
		if err != nil {
			return nil, fmt.Errorf("error collecting to local "+
				"outputs: %w", err)
		}
	}

	// The same for the to_remote, at most one should exist.
	toRemote := fn.Filter(
		allocations, FilterByType(CommitAllocationToRemote),
	)
	switch {
	case len(toRemote) > 1:
		return nil, fmt.Errorf("expected at most one to remote "+
			"output, got %d", len(toRemote))

	case len(toRemote) == 1:
		toRemoteLeaf, err := toRemote[0].AuxLeaf()
		if err != nil {
			return nil, fmt.Errorf("error creating to remote aux "+
				"leaf: %w", err)
		}
		auxLeaves.RemoteAuxLeaf = lfn.Some(toRemoteLeaf)

		remoteAssets, err = collectOutputs(toRemote[0], vPackets)
		if err != nil {
			return nil, fmt.Errorf("error collecting to remote "+
				"outputs: %w", err)
		}
	}

	outgoing := fn.Filter(
		allocations, FilterByType(CommitAllocationHtlcOutgoing),
	)
	for _, a := range outgoing {
		htlcLeaf, err := a.AuxLeaf()
		if err != nil {
			return nil, fmt.Errorf("error creating outgoing htlc "+
				"aux leaf: %w", err)
		}

		if auxLeaves.OutgoingHtlcLeaves == nil {
			auxLeaves.OutgoingHtlcLeaves = make(input.AuxTapLeaves)
		}

		auxLeaves.OutgoingHtlcLeaves[a.HtlcIndex] = input.HtlcAuxLeaf{
			AuxTapLeaf: lfn.Some(htlcLeaf),

			// At this point we cannot derive the second level leaf
			// yet. We'll need to do that right before signing the
			// second level transaction, only then do we know the
			// full commitment transaction to reference.
			SecondLevelLeaf: lfn.None[txscript.TapLeaf](),
		}

		outgoingHtlcs[a.HtlcIndex], err = collectOutputs(a, vPackets)
		if err != nil {
			return nil, fmt.Errorf("error collecting outgoing "+
				"htlc outputs: %w", err)
		}
	}

	incoming := fn.Filter(
		allocations, FilterByType(CommitAllocationHtlcIncoming),
	)
	for _, a := range incoming {
		htlcLeaf, err := a.AuxLeaf()
		if err != nil {
			return nil, fmt.Errorf("error creating incoming htlc "+
				"aux leaf: %w", err)
		}

		if auxLeaves.IncomingHtlcLeaves == nil {
			auxLeaves.IncomingHtlcLeaves = make(input.AuxTapLeaves)
		}

		auxLeaves.IncomingHtlcLeaves[a.HtlcIndex] = input.HtlcAuxLeaf{
			AuxTapLeaf: lfn.Some(htlcLeaf),

			// At this point we cannot derive the second level leaf
			// yet. We'll need to do that right before signing the
			// second level transaction, only then do we know the
			// full commitment transaction to reference.
			SecondLevelLeaf: lfn.None[txscript.TapLeaf](),
		}

		incomingHtlcs[a.HtlcIndex], err = collectOutputs(a, vPackets)
		if err != nil {
			return nil, fmt.Errorf("error collecting incoming "+
				"htlc outputs: %w", err)
		}
	}

	return NewCommitment(
		localAssets, remoteAssets, outgoingHtlcs, incomingHtlcs,
		auxLeaves,
	), nil
}

// collectOutputs collects all virtual transaction outputs for a given
// allocation from the given packets.
func collectOutputs(a *Allocation,
	allPackets []*tappsbt.VPacket) ([]*AssetOutput, error) {

	var outputs []*AssetOutput
	for _, p := range allPackets {
		assetID, err := p.AssetID()
		if err != nil {
			return nil, fmt.Errorf("error getting asset ID of "+
				"packet: %w", err)
		}

		for idx, o := range p.Outputs {
			if o.ProofSuffix == nil {
				return nil, fmt.Errorf("output %v is missing "+
					"proof", idx)
			}
			if o.AnchorOutputIndex == a.OutputIndex {
				outputs = append(outputs, NewAssetOutput(
					assetID, o.Amount, *o.ProofSuffix,
				))
			}
		}
	}

	return outputs, nil
}

// CreateSecondLevelHtlcPackets creates the virtual packets for the second level
// HTLC transaction.
func CreateSecondLevelHtlcPackets(chanState *channeldb.OpenChannel,
	commitTx *wire.MsgTx, htlcAmt btcutil.Amount,
	keys lnwallet.CommitmentKeyRing, chainParams *address.ChainParams,
	htlcOutputs []*AssetOutput) ([]*tappsbt.VPacket, []*Allocation, error) {

	var leaseExpiry uint32
	if chanState.ChanType.HasLeaseExpiration() {
		leaseExpiry = chanState.ThawHeight
	}

	// Next, we'll generate the script used as the output for all second
	// level HTLC which forces a covenant w.r.t what can be done with all
	// HTLC outputs.
	scriptInfo, err := lnwallet.SecondLevelHtlcScript(
		chanState.ChanType, chanState.IsInitiator, keys.RevocationKey,
		keys.ToLocalKey, uint32(chanState.LocalChanCfg.CsvDelay),
		leaseExpiry, lfn.None[txscript.TapLeaf](),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating second level htlc "+
			"script: %w", err)
	}

	sibling, htlcTree, err := LeavesFromTapscriptScriptTree(scriptInfo)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating second level HTLC "+
			"script sibling: %w", err)
	}

	allocations := []*Allocation{{
		Type:         SecondLevelHtlcAllocation,
		Amount:       OutputSum(htlcOutputs),
		AssetVersion: asset.V1,
		BtcAmount:    htlcAmt,
		Sequence: lnwallet.HtlcSecondLevelInputSequence(
			chanState.ChanType,
		),
		InternalKey:    htlcTree.InternalKey,
		NonAssetLeaves: sibling,
		ScriptKey:      asset.NewScriptKey(htlcTree.TaprootKey),
		SortPkScript:   schnorr.SerializePubKey(htlcTree.TaprootKey),
	}}

	// The proofs in the asset outputs don't have the full commitment
	// transaction, so we need to add it now to make them complete.
	inputProofs := fn.Map(htlcOutputs, func(o *AssetOutput) *proof.Proof {
		p := o.Proof.Val
		p.AnchorTx = *commitTx

		return &p
	})

	vPackets, err := DistributeCoins(inputProofs, allocations, chainParams)

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

	return vPackets, allocations, nil
}

// CreateSecondLevelHtlcTx creates the auxiliary leaf for a successful or timed
// out second level HTLC transaction.
func CreateSecondLevelHtlcTx(chanState *channeldb.OpenChannel,
	commitTx *wire.MsgTx, htlcAmt btcutil.Amount,
	keys lnwallet.CommitmentKeyRing, chainParams *address.ChainParams,
	htlcOutputs []*AssetOutput) (input.AuxTapLeaf, error) {

	none := input.NoneTapLeaf()

	vPackets, allocations, err := CreateSecondLevelHtlcPackets(
		chanState, commitTx, htlcAmt, keys, chainParams, htlcOutputs,
	)
	if err != nil {
		return none, fmt.Errorf("error creating second level HTLC "+
			"packets: %w", err)
	}

	outCommitments, err := tapsend.CreateOutputCommitments(vPackets)
	if err != nil {
		return none, fmt.Errorf("unable to create output commitments: "+
			"%w", err)
	}

	// The output commitment is all we need to create the auxiliary leaves.
	// We map the output commitments (which are keyed by on-chain output
	// index) back to the allocation.
	err = AssignOutputCommitments(allocations, outCommitments)
	if err != nil {
		return none, fmt.Errorf("unable to assign output commitments: "+
			"%w", err)
	}

	// Finally, we can create the auxiliary leaf for the second level HTLC
	// transaction.
	auxLeaf, err := allocations[0].AuxLeaf()
	if err != nil {
		return none, fmt.Errorf("error creating aux leaf: %w", err)
	}
	return lfn.Some(auxLeaf), nil
}

// InPlaceCustomCommitSort performs an in-place sort of a transaction, given a
// list of allocations. The sort is applied to the transaction outputs, using
// the allocation's OutputIndex. The transaction inputs are sorted by the
// default BIP69 sort.
func InPlaceCustomCommitSort(tx *wire.MsgTx, cltvs []uint32,
	allocations []*Allocation) error {

	if len(tx.TxOut) != len(allocations) {
		return fmt.Errorf("output and allocation size mismatch")
	}

	if len(tx.TxOut) != len(cltvs) {
		return fmt.Errorf("output and cltv list size mismatch")
	}

	// First the easy part, sort the inputs by BIP69.
	sort.Sort(sortableInputSlice(tx.TxIn))

	// We simply create a backup of the outputs first, then completely
	// re-create the outputs in the desired order.
	txOutOriginal := tx.TxOut
	tx.TxOut = make([]*wire.TxOut, len(tx.TxOut))

	for i, original := range txOutOriginal {
		var allocation *Allocation
		for _, a := range allocations {
			match, err := a.MatchesOutput(
				original.PkScript, original.Value, cltvs[i],
			)
			if err != nil {
				return fmt.Errorf("error matching output: %w",
					err)
			}

			if match {
				allocation = a
				break
			}
		}

		if allocation == nil {
			return fmt.Errorf("no corresponding allocation entry "+
				"found for output index %d", i)
		}

		newOrder := allocation.OutputIndex
		if newOrder >= uint32(len(tx.TxOut)) {
			return fmt.Errorf("order index %d out of bounds "+
				"(num_tx_out=%d)", newOrder, len(tx.TxOut))
		}

		tx.TxOut[newOrder] = &wire.TxOut{
			Value:    original.Value,
			PkScript: original.PkScript,
		}
	}

	return nil
}

// sortableInputSlice is a slice of transaction inputs that supports sorting via
// BIP69.
type sortableInputSlice []*wire.TxIn

// Len returns the length of the sortableInputSlice.
//
// NOTE: Part of the sort.Interface interface.
func (s sortableInputSlice) Len() int { return len(s) }

// Swap exchanges the position of inputs i and j.
//
// NOTE: Part of the sort.Interface interface.
func (s sortableInputSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// Less is the BIP69 input comparison function. The sort is first applied on
// input hash (reversed / rpc-style), then index. This logic is copied from
// btcutil/txsort.
//
// NOTE: Part of the sort.Interface interface.
func (s sortableInputSlice) Less(i, j int) bool {
	// Input hashes are the same, so compare the index.
	ihash := s[i].PreviousOutPoint.Hash
	jhash := s[j].PreviousOutPoint.Hash
	if ihash == jhash {
		return s[i].PreviousOutPoint.Index < s[j].PreviousOutPoint.Index
	}

	// At this point, the hashes are not equal, so reverse them to
	// big-endian and return the result of the comparison.
	const hashSize = chainhash.HashSize
	for b := 0; b < hashSize/2; b++ {
		ihash[b], ihash[hashSize-1-b] = ihash[hashSize-1-b], ihash[b]
		jhash[b], jhash[hashSize-1-b] = jhash[hashSize-1-b], jhash[b]
	}
	return bytes.Compare(ihash[:], jhash[:]) == -1
}
