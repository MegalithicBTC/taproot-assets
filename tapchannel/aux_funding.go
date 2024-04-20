package tapchannel

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"fmt"
	"io"
	"sync/atomic"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/channeldb"
	lfn "github.com/lightningnetwork/lnd/fn"
	"github.com/lightningnetwork/lnd/funding"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/lightningnetwork/lnd/lnwire"
)

var (
	// p2trChangeType is the type of change address that should be used for
	// funding PSBTs, as we'll always want to use P2TR change addresses.
	p2trChangeType = walletrpc.ChangeAddressType_CHANGE_ADDRESS_TYPE_P2TR
)

// ErrorReporter is used to report an error back to the caller and/or peer that
// we're communicating with.
type ErrorReporter interface {
	// ReportError reports an error that occurred during the funding
	// process.
	ReportError(pid funding.PendingChanID, err error)
}

// PeerMessenger is an interface that allows us to send messages to a remote LN
// peer.
type PeerMessenger interface {
	// SendMessage sends a message to a remote peer.
	SendMessage(ctx context.Context, peer btcec.PublicKey,
		msg lnwire.Message) error
}

// OpenChanReq is a request to open a new asset channel with a remote peer.
type OpenChanReq struct {
	// ChanAmt is the amount of BTC to put into the channel. Some BTC is
	// required atm to pay on chain fees for the channel. Note that
	// additional fees can be added in the event of a force close by using
	// CPFP with the channel anchor outputs.
	ChanAmt btcutil.Amount

	// PeerPub is the identity public key of the remote peer we wish to
	// open the channel with.
	PeerPub btcec.PublicKey

	// TempPID is the temporary channel ID to use for this channel.
	TempPID funding.PendingChanID

	// PsbtTemplate is the PSBT template that we'll use to fund the
	// channel.  This should already have all the inputs spending asset
	// UTXOs added.
	PsbtTemplate *psbt.Packet
}

// AssetChanIntent is a handle returned by the PsbtChannelFunder that can be
// used to drive the new asset channel to completion. The intent includes the
// PSBT template returned by lnd which has the funding output for the new
// channel already populated.
type AssetChanIntent interface {
	// FundingPsbt is the original PsbtTemplate, plus the P2TR funding output
	// that'll create the channel.
	FundingPsbt() (*psbt.Packet, error)

	// BindPsbt accepts a new *unsigned* PSBT with any additional inputs or
	// outputs (for change) added. This PSBT is still unsigned. This step
	// performs final verification to ensure the PSBT is crafted in a manner
	// that'll properly open the channel once broadcaster.
	BindPsbt(context.Context, *psbt.Packet) error
}

// PsbtChannelFunder is an interface that abstracts the necessary steps needed
// fund a PSBT channel on using lnd.
type PsbtChannelFunder interface {
	// OpenChannel attempts to open a new asset holding private channel
	// using the backing lnd node. The PSBT flow is by default. An
	// AssetChanIntent is returned that includes the updated PSBT template
	// that includes the funding output. Once all other inputs+outputs have
	// been added, then BindPsbt should be called to progress the funding
	// process. Afterwards, the funding transaction should be
	// signed+broadcast.
	OpenChannel(context.Context, OpenChanReq) (AssetChanIntent, error)
}

// TxPublisher is an interface used to publish transactions.
type TxPublisher interface {
	// PublishTransaction attempts to publish a new transaction to the
	// network.
	PublishTransaction(context.Context, *wire.MsgTx) error
}

// FundingControllerCfg is a configuration struct that houses the necessary
// abstractions needed to drive funding.
type FundingControllerCfg struct {
	// HeaderVerifier is used to verify headers in a proof.
	HeaderVerifier proof.HeaderVerifier

	// GroupVerifier is used to verify group keys in a proof.
	GroupVerifier proof.GroupVerifier

	// ErrReporter is used to report errors back to the caller and/or peer.
	ErrReporter ErrorReporter

	// AssetWallet is the wallet that we'll use to handle the asset
	// specific steps of the funding process.
	AssetWallet tapfreighter.Wallet

	CoinSelector tapfreighter.CoinSelector

	// ChainParams is the chain params of the chain we operate on.
	ChainParams address.ChainParams

	// GroupKeyIndex is used to query the group key for an asset ID.
	GroupKeyIndex tapsend.AssetGroupQuerier

	// PeerMessenger is used to send messages to a remote peer.
	//
	// TODO(roasbeef): in memory hook directly into SendMsg?
	PeerMessenger PeerMessenger

	// ChannelFunder is used to fund a new channel using a PSBT template.
	ChannelFunder PsbtChannelFunder

	// TxPublisher is used to publish transactions.
	TxPublisher TxPublisher

	// ChainWallet is the wallet that we'll use to handle the chain
	// specific
	ChainWallet tapgarden.WalletAnchor
}

// bindFundingReq is a request to bind a pending channel ID to a complete aux
// funding desc. This is used by the initiator+responder after the pre funding
// messages and interaction is complete.
type bindFundingReq struct {
	initiator bool

	tempPID funding.PendingChanID

	openChan *channeldb.OpenChannel

	localKeyRing lnwallet.CommitmentKeyRing

	remoteKeyRing lnwallet.CommitmentKeyRing

	resp chan lfn.Option[lnwallet.AuxFundingDesc]
}

// assetRootReq is a message sent by lnd once we've sent the or received the
// OpenChannel message. We'll reply with a tapscript root if we know of one for
// this pid, which lets lnd derive the proper funding output.
type assetRootReq struct {
	tempPID funding.PendingChanID

	resp chan lfn.Option[chainhash.Hash]
}

// FundingController is used to drive TAP aware channel funding using a backing
// lnd node and an active connection to a tapd instance.
type FundingController struct {
	started atomic.Bool
	stopped atomic.Bool

	cfg FundingControllerCfg

	msgs chan lnwire.Message

	bindFundingReqs chan *bindFundingReq

	newFundingReqs chan *FundReq

	rootReqs chan *assetRootReq

	// ContextGuard provides a wait group and main quit channel that can be
	// used to create guarded contexts.
	*fn.ContextGuard
}

// NewFundingController creates a new instance of the FundingController.
func NewFundingController(cfg FundingControllerCfg) *FundingController {
	return &FundingController{
		cfg:             cfg,
		msgs:            make(chan lnwire.Message, 10),
		bindFundingReqs: make(chan *bindFundingReq, 10),
		newFundingReqs:  make(chan *FundReq, 10),
		rootReqs:        make(chan *assetRootReq, 10),
		ContextGuard: &fn.ContextGuard{
			DefaultTimeout: DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}
}

// Start starts the funding controller.
func (f *FundingController) Start() error {
	if !f.started.CompareAndSwap(false, true) {
		return nil
	}

	log.Infof("Starting FundingController")

	f.Wg.Add(1)
	go f.chanFunder()

	return nil
}

// Stop stops the funding controller.
func (f *FundingController) Stop() error {
	if !f.started.CompareAndSwap(true, false) {
		return nil
	}

	log.Infof("Stopping FundingController")

	return nil
}

// newPendingChanID generates a new pending channel ID using a CSPRG.
func newPendingChanID() (funding.PendingChanID, error) {
	var id funding.PendingChanID
	if _, err := io.ReadFull(crand.Reader, id[:]); err != nil {
		return id, err
	}

	return id, nil
}

// pendingAssetFunding represents all the state needed to keep track of a
// pending asset channel funding flow.
type pendingAssetFunding struct {
	peerPub btcec.PublicKey

	pid funding.PendingChanID

	initiator bool

	// TODO(roasbeef): should be the new Either identifier?
	assetID asset.ID

	amt uint64

	proofs []*proof.Proof

	feeRate chainfee.SatPerVByte

	lockedInputs []wire.OutPoint

	lockedAssetInputs []wire.OutPoint

	fundingAssetCommitment *commitment.TapCommitment

	fundingOutputProofs []*proof.Proof
}

// addProof adds a new proof to the set of proofs that'll be used to fund the
// new channel.
func (p *pendingAssetFunding) addProof(proof *proof.Proof) {
	p.proofs = append(p.proofs, proof)
}

// assetOutputs returns the set of asset outputs that'll be used to fund the
// new asset channel.
func (p *pendingAssetFunding) assetOutputs() []*AssetOutput {
	return fn.Map(p.fundingOutputProofs, func(p *proof.Proof) *AssetOutput {
		asset := p.Asset
		return NewAssetOutput(asset.ID(), asset.Amount, *p)
	})
}

// newCommitBlobAndLeaves creates a new commitment blob that'll be stored in
// the channel state for the specified party.
func newCommitBlobAndLeaves(fundingState *pendingAssetFunding,
	leafCreator *AuxLeafCreator, lndOpenChan *channeldb.OpenChannel,
	assetOpenChan *OpenChannel, keyRing lnwallet.CommitmentKeyRing,
	initiator bool) ([]byte, lnwallet.CommitAuxLeaves, error) {

	var (
		localAssets, remoteAssets []*AssetOutput
	)
	if initiator {
		localAssets = assetOpenChan.FundedAssets.Val.outputs
	} else {
		remoteAssets = assetOpenChan.FundedAssets.Val.outputs
	}

	var localSatBalance, remoteSatBalance lnwire.MilliSatoshi

	// We don't have a real prev state at this point, the leaf creator only
	// needs the sum of the remote+local assets, so we'll populate that.
	fakePrevState := NewCommitment(
		localAssets, remoteAssets, nil, nil, lnwallet.CommitAuxLeaves{},
	)

	// Just like above, we don't have a real HTLC view here, so we'll pass
	// in a blank view.
	fakeView := &lnwallet.HtlcView{}

	// With all the above, we'll generate the first commitment that'll be
	// stored
	_, firstCommit, err := leafCreator.generateAllocations(
		fakePrevState, lndOpenChan, assetOpenChan, initiator,
		localSatBalance, remoteSatBalance, fakeView, keyRing,
	)
	if err != nil {
		return nil, lnwallet.CommitAuxLeaves{}, err
	}

	var b bytes.Buffer
	if err := firstCommit.Encode(&b); err != nil {
		return nil, lnwallet.CommitAuxLeaves{}, err
	}

	auxLeaves := firstCommit.Leaves()

	return b.Bytes(), auxLeaves, nil
}

// toAuxFundingDesc converts the pending asset funding into a full aux funding
// desc. This is the final step in the modified funding process, as after this,
// both sides are able to construct the funding output, and will be able to
// store the appropriate funding blobs.
func (p *pendingAssetFunding) toAuxFundingDesc(chainParams address.ChainParams,
	req *bindFundingReq) (*lnwallet.AuxFundingDesc, error) {

	var fundingDesc lnwallet.AuxFundingDesc

	// First, we'll map all the assets into asset outputs that'll be stored
	// in the open channel struct on the lnd side.
	assetOutputs := p.assetOutputs()

	// With all the outputs assembled, we'll now map that to the open
	// channel wrapper that'll go in the set of TLV blobs.
	openChanDesc := NewOpenChannel(assetOutputs)

	// Now we'll encode the 3 TLV blobs that lnd will store: the main one
	// for the funding details, and then the blobs for the local and remote
	// commitment
	fundingDesc.CustomFundingBlob = openChanDesc.Bytes()

	auxLeafStore := NewAuxLeafCreator(&LeafCreatorConfig{
		ChainParams: &chainParams,
	})

	// Encode the commitment blobs for both the local and remote party.
	// This will be the information for the very first state (state 0).
	var err error
	fundingDesc.CustomLocalCommitBlob, fundingDesc.LocalInitAuxLeaves, err = newCommitBlobAndLeaves(
		p, auxLeafStore, req.openChan, openChanDesc, req.localKeyRing,
		p.initiator,
	)
	if err != nil {
		return nil, err
	}
	fundingDesc.CustomRemoteCommitBlob, fundingDesc.RemoteInitAuxLeaves, err = newCommitBlobAndLeaves(
		p, auxLeafStore, req.openChan, openChanDesc, req.remoteKeyRing,
		!p.initiator,
	)
	if err != nil {
		return nil, err
	}

	return &fundingDesc, nil
}

// unlockInputs unlocks any inputs that were locked during the funding process.
func (p *pendingAssetFunding) unlockInputs(ctx context.Context,
	wallet tapgarden.WalletAnchor) error {

	for _, outpoint := range p.lockedInputs {
		if err := wallet.UnlockInput(ctx, outpoint); err != nil {
			return fmt.Errorf("unable to unlock outpoint %v: %v",
				outpoint, err)
		}

	}

	return nil
}

// unlockAssetInputs unlocks any asset inputs that were locked during the
// funding process.
func (p *pendingAssetFunding) unlockAssetInputs(ctx context.Context,
	coinSelect tapfreighter.CoinSelector) error {

	err := coinSelect.ReleaseCoins(ctx, p.lockedAssetInputs...)
	if err != nil {
		return fmt.Errorf("unable to unlock asset outpoints %v: %w",
			p.lockedAssetInputs, err)
	}

	return nil
}

// msgToAssetProof converts a wire message to an assetProof.
func msgToAssetProof(msg lnwire.Message) (AssetFundingMsg, error) {
	switch msg := msg.(type) {
	case *lnwire.Custom:
		switch msg.Type {
		case TxAssetInputProofType:
			var assetProof TxAssetInputProof
			err := assetProof.Decode(bytes.NewReader(msg.Data), 0)
			if err != nil {
				return nil, fmt.Errorf("error decoding as "+
					"tx asset input proof: %w", err)
			}

			return &assetProof, nil

		case TxAssetOutputProofType:
			var assetProof TxAssetOutputProof
			err := assetProof.Decode(bytes.NewReader(msg.Data), 0)
			if err != nil {
				return nil, fmt.Errorf("error decoding as "+
					"tx asset output proof: %w", err)
			}

			return &assetProof, nil

		case AssetFundingCreatedType:
			var assetProof AssetFundingCreated
			err := assetProof.Decode(bytes.NewReader(msg.Data), 0)
			if err != nil {
				return nil, fmt.Errorf("error decoding as "+
					"asset funding created: %w", err)
			}

			return &assetProof, nil
		default:
			return nil, fmt.Errorf("unknown custom message "+
				"type: %v", msg.Type)
		}

	case *TxAssetInputProof:
		return msg, nil

	case *TxAssetOutputProof:
		return msg, nil

	case *AssetFundingCreated:
		return msg, nil

	default:
		return nil, fmt.Errorf("unknown message type: %T", msg)
	}
}

// fundingFlowIndex is a map from pending channel ID to the current state of
// the funding flow.
type fundingFlowIndex map[funding.PendingChanID]*pendingAssetFunding

// fromMsg attempts to match an incoming message to the pending funding flow,
// and extracts the asset proof from the message.
func (f *fundingFlowIndex) fromMsg(
	msg lnwire.Message) (AssetFundingMsg, *pendingAssetFunding, error) {

	assetProof, err := msgToAssetProof(msg)
	if err != nil {
		return nil, nil, fmt.Errorf("error converting to asset proof: "+
			"%w", err)
	}

	assetID := assetProof.FundingAssetID()
	tempPID := assetProof.PendingChanID()

	// Next, we'll see if this is already part of an active
	// funding flow. If not, then we'll make a new one to
	// accumulate this new proof.
	assetFunding, ok := (*f)[tempPID]
	if !ok {
		assetFunding = &pendingAssetFunding{
			pid:     tempPID,
			assetID: assetID,
			amt:     assetProof.Amt(),
		}
		(*f)[tempPID] = assetFunding

	}

	return assetProof, assetFunding, nil
}

// fundVpkt attempts to fund a new vPacket using the asset wallet to find the
// asset inputs required to satisfy a funding request.
func (f *FundingController) fundVpkt(ctx context.Context, assetID asset.ID,
	amt uint64) (*tapfreighter.FundedVPacket, error) {

	log.Infof("Funding new vPacket channel, asset_id=%v, amt=%v",
		assetID, amt)

	// Our funding script key will be the OP_TRUE addr that we'll use as
	// the funding script on the asset level.
	fundingScriptTree := NewFundingScriptTree()
	fundingScriptKey := asset.NewScriptKey(fundingScriptTree.TaprootKey)

	// Next, we'll use the asset wallet to fund a new vPSBT which'll be
	// used as the asset level funding output for this transaction. In this
	// case our destination will just be the OP_TRUE tapscript that we use
	// for the funding output.
	pktTemplate := &tappsbt.VPacket{
		Inputs: []*tappsbt.VInput{{
			PrevID: asset.PrevID{
				ID: assetID,
			},
		}},
		Outputs: []*tappsbt.VOutput{{
			Amount:            amt,
			AssetVersion:      asset.V1,
			Interactive:       true,
			AnchorOutputIndex: 0,
			ScriptKey:         fundingScriptKey,
		}},
		ChainParams: &f.cfg.ChainParams,
	}
	fundDesc, err := tapsend.DescribeRecipients(
		ctx, pktTemplate, f.cfg.GroupKeyIndex,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to describe recipients: %v", err)
	}

	// Fund the packet. This will derive an anchor internal key for us, but
	// we'll overwrite that later on.
	return f.cfg.AssetWallet.FundPacket(
		ctx, fundDesc, pktTemplate,
	)
}

// sendInputOwnershipProofs sends the input ownership proofs to the remote
// party during the validation phase of the funding process.
func (f *FundingController) sendInputOwnershipProofs(peerPub btcec.PublicKey,
	vpkt *tappsbt.VPacket, fundingState *pendingAssetFunding) error {

	ctx, done := f.WithCtxQuit()
	defer done()

	log.Infof("Generating input ownership proofs for %v inputs",
		len(vpkt.Inputs))

	// For each of the inputs we selected, we'll create a new ownership
	// proof for each of them. We'll send this to the peer so they can
	// verify that we actually own the inputs we're using to fund
	// the channel.
	for _, assetInput := range vpkt.Inputs {
		// First, we'll grab the proof for the asset input, then
		// generate the challenge witness to place in the proof so it
		challengeWitness, err := f.cfg.AssetWallet.SignOwnershipProof(
			assetInput.Asset(),
		)
		if err != nil {
			return fmt.Errorf("error signing ownership "+
				"proof: %w", err)
		}

		// TODO(roasbeef): use the temp chan ID above? as part of
		// challenge

		// With the witness obtained, we'll emplace it, then add this
		// to our set of relevant input proofs. But we create a copy of
		// the proof first, to make sure we don't modify the vPacket.
		var proofBuf bytes.Buffer
		err = assetInput.Proof.Encode(&proofBuf)
		if err != nil {
			return fmt.Errorf("error serializing proof: %w", err)
		}

		proofCopy := &proof.Proof{}
		if err := proofCopy.Decode(&proofBuf); err != nil {
			return fmt.Errorf("error decoding proof: %w", err)
		}

		proofCopy.ChallengeWitness = challengeWitness
		fundingState.proofs = append(fundingState.proofs, proofCopy)
	}

	// With all our proofs assembled, we'll now send each of them to the
	// remote peer in series.
	for i := range fundingState.proofs {
		inputProof := NewTxAssetInputProof(
			fundingState.pid, *fundingState.proofs[i],
		)

		// Finally, we'll send the proof to the remote peer.
		err := f.cfg.PeerMessenger.SendMessage(ctx, peerPub, inputProof)
		if err != nil {
			return fmt.Errorf("unable to send proof to "+
				"peer: %v", err)
		}
	}

	// Now that we've sent the proofs for the input assets, we'll send them
	// a fully signed asset funding output. We can send this safely as they
	// can't actually broadcast this without our signed Bitcoin inputs.
	//
	// TODO(roasbeef): generalize for multi-asset
	fundingAsset := vpkt.Outputs[0].Asset.Copy()
	assetOutputMsg := NewTxAssetOutputProof(fundingState.pid, *fundingAsset)

	log.Infof("Sending TLV for funding asset output to remote "+
		"party: %v", spew.Sdump(fundingAsset))

	err := f.cfg.PeerMessenger.SendMessage(ctx, peerPub, assetOutputMsg)
	if err != nil {
		return fmt.Errorf("unable to send proof to "+
			"peer: %v", err)
	}

	return nil
}

// fundPsbt takes our PSBT anchor template and has lnd fund the PSBT with
// enough inputs and a proper change output.
func (f *FundingController) fundPsbt(
	ctx context.Context, psbtPkt *psbt.Packet,
	feeRate chainfee.SatPerKWeight) (*tapsend.FundedPsbt, error) {

	// We set the change index to be a new, 3rd output by specifying -1
	// (which means: please add change output). We could instead have it be
	// the second output, but that would mingle lnd's funds with outputs
	// that mainly store assets.
	changeIndex := int32(-1)
	return f.cfg.ChainWallet.FundPsbt(ctx, psbtPkt, 1, feeRate, changeIndex)
}

// signAllVPackets takes the funding vPSBT, signs all the explicit transfer,
// and then derives all the passive transfers that also needs to be signed, and
// then signs those. A single slice of all the passive and active assets signed
// is returned.
func (f *FundingController) signAllVPackets(ctx context.Context,
	fundingVpkt *tapfreighter.FundedVPacket) ([]*tappsbt.VPacket, error) {

	log.Infof("Signing all funding vPackets")

	activePkt := fundingVpkt.VPacket

	encoded, err := tappsbt.Encode(activePkt)
	log.Debugf("Active packet: %x", encoded)

	_, err = f.cfg.AssetWallet.SignVirtualPacket(activePkt)
	if err != nil {
		return nil, fmt.Errorf("unable to sign and commit "+
			"virtual packet: %w", err)
	}

	passivePkts, err := f.cfg.AssetWallet.CreatePassiveAssets(
		ctx, []*tappsbt.VPacket{activePkt},
		fundingVpkt.InputCommitments,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create passive "+
			"assets: %w", err)
	}
	err = f.cfg.AssetWallet.SignPassiveAssets(passivePkts)
	if err != nil {
		return nil, fmt.Errorf("unable to sign passive assets: %w", err)
	}

	allPackets := append([]*tappsbt.VPacket{}, activePkt)
	allPackets = append(allPackets, passivePkts...)

	return allPackets, nil
}

// anchorVPackets anchors the vPackets to the funding PSBT, creating a
// complete, but unsigned PSBT packet that can be used to create out asset
// channel.
func (f *FundingController) anchorVPackets(fundedPkt *tapsend.FundedPsbt,
	allPackets []*tappsbt.VPacket,
	fundingScriptKey asset.ScriptKey) ([]*proof.Proof, error) {

	log.Infof("Anchoring funding vPackets to funding PSBT")

	// Given the set of vPackets we've created, we'll now now merge them
	// all to create a map from output index to final tap commitment.
	outputCommitments, err := tapsend.CreateOutputCommitments(allPackets)
	if err != nil {
		return nil, fmt.Errorf("unable to create new output "+
			"commitments: %w", err)
	}

	// Now that we know all the output commitments, we can modify the
	// Bitcoin PSBT to have the proper pkScript that commits to the newly
	// anchored assets.
	for _, vPkt := range allPackets {
		err = tapsend.UpdateTaprootOutputKeys(
			fundedPkt.Pkt, vPkt, outputCommitments,
		)
		if err != nil {
			return nil, fmt.Errorf("error updating taproot output "+
				"keys: %w", err)
		}
	}

	var fundingProofs []*proof.Proof

	// We're done creating the output commitments, we can now create the
	// transition proof suffixes. This'll be the new proof we submit to
	// relevant universe (or not) to update the new resting place of these
	// assets.
	for idx := range allPackets {
		vPkt := allPackets[idx]

		for vOutIdx := range vPkt.Outputs {
			proofSuffix, err := tapsend.CreateProofSuffix(
				fundedPkt.Pkt.UnsignedTx, fundedPkt.Pkt.Outputs,
				vPkt, outputCommitments, vOutIdx, allPackets,
			)
			if err != nil {
				return nil, fmt.Errorf("unable to create proof "+
					"suffix for output %d of vPSBT %d: %w",
					vOutIdx, idx, err)
			}

			vPkt.Outputs[vOutIdx].ProofSuffix = proofSuffix

			if proofSuffix.Asset.ScriptKey.PubKey.IsEqual(fundingScriptKey.PubKey) {
				fundingProofs = append(fundingProofs, proofSuffix)
			}
		}
	}

	return fundingProofs, nil
}

// signAndFinalizePsbt signs and finalizes the PSBT, then returns the finalized
// transaction, but only after sanity checks pass.
func (f *FundingController) signAndFinalizePsbt(ctx context.Context,
	pkt *psbt.Packet) (*wire.MsgTx, error) {

	log.Infof("Signing and finalizing PSBT w/ lnd")

	signedPkt, err := f.cfg.ChainWallet.SignAndFinalizePsbt(ctx, pkt)
	if err != nil {
		return nil, fmt.Errorf("unable to finalize PSBT: %v", err)
	}

	// Extra the tx manually, then perform some manual sanity checks to
	// make sure things are ready for broadcast.
	//
	// TODO(roasbeef): could also do testmempoolaccept here
	signedTx, err := psbt.Extract(signedPkt)
	if err != nil {
		return nil, fmt.Errorf("unable to extract psbt: %w", err)
	}
	err = blockchain.CheckTransactionSanity(btcutil.NewTx(signedTx))
	if err != nil {
		return nil, fmt.Errorf("genesis TX failed final checks: "+
			"%w", err)
	}

	return signedTx, nil
}

// sendAssetFundingCreated sends the AssetFundingCreated message to the remote
// party.
func (f *FundingController) sendAssetFundingCreated(ctx context.Context,
	fundingState *pendingAssetFunding) error {

	log.Infof("Sending AssetFundingCreated")

	assetFundingCreated := NewAssetFundingCreated(
		fundingState.pid, *fundingState.fundingOutputProofs[0],
	)

	return f.cfg.PeerMessenger.SendMessage(
		ctx, fundingState.peerPub, assetFundingCreated,
	)
}

// completeChannelFunding is the final step in the funding process. This is
// launched as a goroutine after all the input ownership proofs have been sent.
// This method handles the final process of funding+signing the PSBT+vPSBT,
// then presenting the final funding transaction to lnd for validation, before
// ultimately broadcasting the funding transaction.
func (f *FundingController) completeChannelFunding(ctx context.Context,
	fundingState *pendingAssetFunding,
	fundedVpkt *tapfreighter.FundedVPacket) (*chainhash.Hash, error) {

	log.Infof("Finalizing funding vPackets and PSBT...")

	// Now that we have the initial PSBT template, we can start the funding
	// flow with lnd.
	fundingReq := OpenChanReq{
		ChanAmt: funding.MinChanFundingSize,
		PeerPub: fundingState.peerPub,
		TempPID: fundingState.pid,
	}
	assetChanIntent, err := f.cfg.ChannelFunder.OpenChannel(ctx, fundingReq)
	if err != nil {
		return nil, fmt.Errorf("unable to open channel: %v", err)
	}

	// Now that we have the intent back from lnd, we can use the PSBT
	// information returned to set the proper internal key information for
	// the vPSBT funding output.
	psbtWithFundingOutput, err := assetChanIntent.FundingPsbt()
	if err != nil {
		return nil, fmt.Errorf("unable to get funding PSBT: %w", err)
	}
	internalKeyBytes := psbtWithFundingOutput.Outputs[0].TaprootInternalKey

	log.Infof("Swapping in true taproot internal key: %x",
		internalKeyBytes)

	fundingInternalKey, err := schnorr.ParsePubKey(internalKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse internal key: %w", err)
	}

	fundedVpkt.VPacket.Outputs[0].AnchorOutputBip32Derivation = nil
	fundedVpkt.VPacket.Outputs[0].AnchorOutputTaprootBip32Derivation = nil
	fundingInternalKeyDesc := keychain.KeyDescriptor{
		PubKey: fundingInternalKey,
	}
	fundedVpkt.VPacket.Outputs[0].SetAnchorInternalKey(
		fundingInternalKeyDesc, f.cfg.ChainParams.HDCoinType,
	)

	// Given the asset inputs selected in the prior step, we'll now
	// construct a template packet that maps our asset inputs to actual
	// inputs in the PSBT packet.
	fundingVPkts := []*tappsbt.VPacket{fundedVpkt.VPacket}
	fundingPsbt, err := tapsend.PrepareAnchoringTemplate(fundingVPkts)
	if err != nil {
		return nil, err
	}

	fundingState.lockedAssetInputs = fn.Map(
		fundedVpkt.VPacket.Inputs,
		func(in *tappsbt.VInput) wire.OutPoint {
			return in.PrevID.OutPoint
		},
	)

	// Now that we have the initial skeleton for our funding PSBT, we'll
	// modify the output value to match the channel amt asked for, which
	// lnd will expect.
	//
	// Later on, after we anchor the vPSBT to the PSBT, we'll then verify
	// with lnd that we arrived at the proper TxOut.
	fundingPsbt.UnsignedTx.TxOut[0].Value = int64(fundingReq.ChanAmt)

	log.Infof("Funding PSBT pre funding: %s", spew.Sdump(fundingPsbt))

	// With the PSBT template created, we'll now ask lnd to fund the PSBT.
	// This'll add yet another output (lnd's change output) to the
	// template.
	finalFundedPsbt, err := f.fundPsbt(
		ctx, fundingPsbt, fundingState.feeRate.FeePerKWeight(),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to fund PSBT: %v", err)
	}

	log.Infof("Funding PSBT post funding: %s", spew.Sdump(finalFundedPsbt))

	// If we fail at any step in the process, we want to make sure we
	// unlock the inputs, so we'll add them to funding state now.
	fundingState.lockedInputs = finalFundedPsbt.LockedUTXOs

	// TODO(roasbeef): verify the PSBT matches up

	// With the PSBT fully funded, we'll now sign all the vPackets before
	// we finalize anchor them concretely into our PSBt.
	signedPkts, err := f.signAllVPackets(ctx, fundedVpkt)
	if err != nil {
		return nil, fmt.Errorf("unable to sign vPackets: %v", err)
	}

	// With all the vPackets signed, we'll now anchor them to the funding
	// PSBT. This'll update all the pkScripts for our funding output and
	// change.
	fundingScriptTree := NewFundingScriptTree()
	fundingScriptKey := asset.NewScriptKey(fundingScriptTree.TaprootKey)
	fundingOutputProofs, err := f.anchorVPackets(
		finalFundedPsbt, signedPkts, fundingScriptKey,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to anchor vPackets: %v", err)
	}

	// Now that we've anchored the packets, we'll also set the fundingVOuts
	// which we'll use later to send the AssetFundingCreated message to the
	// responder, and also return the full AuxFundingDesc back to lnd.
	fundingState.fundingOutputProofs = fundingOutputProofs

	// Before we send the finalized PSBT to lnd, we'll send the
	// AssetFundingCreated message which will preceded the normal
	// FundingCreated message.
	if err := f.sendAssetFundingCreated(ctx, fundingState); err != nil {
		return nil, fmt.Errorf("unable to send "+
			"AssetFundingCreated: %w", err)
	}

	log.Infof("Submitting finalized PSBT to lnd for verification: %s",
		spew.Sdump(finalFundedPsbt.Pkt))

	// At this point, we're nearly done, we'll now present the final PSBT
	// to lnd to verification. If this passes, then we're clear to
	// sign+broadcast the funding transaction.
	err = assetChanIntent.BindPsbt(ctx, finalFundedPsbt.Pkt)
	if err != nil {
		return nil, fmt.Errorf("unable to bind PSBT: %v", err)
	}

	log.Infof("PSBT bound, now signing and broadcasting")

	// At this point, we're all clear, so we'll ask lnd to sign the PSBT
	// (all the input information is in place) and also finalize it.
	signedFundingTx, err := f.signAndFinalizePsbt(ctx, finalFundedPsbt.Pkt)
	if err != nil {
		return nil, fmt.Errorf("unable to finalize PSBT: %v", err)
	}

	// To conclude, we'll now broadcast the transaction, then return the
	// TXID information back to the caller.
	//
	// TODO(roasbeef): return asset stuff too?
	err = f.cfg.TxPublisher.PublishTransaction(ctx, signedFundingTx)
	if err != nil {
		return nil, fmt.Errorf("unable to broadcast funding "+
			"txn: %v", err)
	}

	fundingTxid := signedFundingTx.TxHash()

	log.Infof("Funding transaction broadcast: %v", fundingTxid)

	return &fundingTxid, nil
}

// chanFunder is the main event loop that controls the asset specific portions
// of the funding request.
func (f *FundingController) chanFunder() {
	defer f.Wg.Done()

	fundingFlows := make(fundingFlowIndex)

	for {
		select {

		// A new funding request has arrived. We'll set up the funding
		// state, send our input proofs, then kick off the channel
		// funding asynchronously.
		case fundReq := <-f.newFundingReqs:
			// To start, we'll make a new pending asset funding
			// desc. This'll be our scratch pad during the asset
			// funding process.
			tempPID, err := newPendingChanID()
			if err != nil {
				log.Errorf("unable to create new pending "+
					"chan ID: %v", err)

				fundReq.errChan <- err
				continue
			}
			fundingState := &pendingAssetFunding{
				peerPub:   fundReq.PeerPub,
				pid:       tempPID,
				initiator: true,
				assetID:   fundReq.AssetID,
				amt:       fundReq.Amt,
				feeRate:   fundReq.FeeRate,
			}

			fundingFlows[tempPID] = fundingState

			// With our initial state created, we'll now attempt to
			// fund the channel on the TAP level with a vPacket.
			fundingVpkt, err := f.fundVpkt(
				fundReq.ctx, fundReq.AssetID, fundReq.Amt,
			)
			if err != nil {
				fErr := fmt.Errorf("unable to fund "+
					"vPacket: %v", err)
				log.Error(fErr)
				fundReq.errChan <- fErr
				continue
			}

			// Now that we know the final funding asset root along
			// with the splits, we can derive the tapscript root
			// that'll be used along side the internal key (which
			// we'll only learn from lnd later as we finalize the
			// funding PSBT).
			fundingAsset := fundingVpkt.VPacket.Outputs[0].Asset.Copy()
			fundingCommitment, err := commitment.FromAssets(
				fundingAsset,
			)
			if err != nil {
				fErr := fmt.Errorf("unable to create "+
					"commitment: %v", err)
				log.Error(fErr)
				fundReq.errChan <- fErr
				continue
			}

			fundingState.fundingAssetCommitment = fundingCommitment

			tapsend.LogCommitment(
				"funding output", 0, fundingCommitment,
				&btcec.PublicKey{}, nil, nil,
			)

			// Before we can send our OpenChannel message, we'll
			// need to derive then send a series of ownership
			// proofs to the remote party.
			err = f.sendInputOwnershipProofs(
				fundReq.PeerPub, fundingVpkt.VPacket,
				fundingState,
			)
			if err != nil {
				fErr := fmt.Errorf("unable to send input "+
					"ownership proofs: %v", err)
				log.Error(fErr)
				fundReq.errChan <- fErr
				continue
			}

			// With the ownership proof sent, we'll now spawn a
			// goroutine to take care of the final funding steps.
			f.Wg.Add(1)
			go func() {
				defer f.Wg.Done()
				fundingTxid, err := f.completeChannelFunding(
					fundReq.ctx, fundingState, fundingVpkt,
				)
				if err != nil {
					// If we've failed, then we'll unlock
					// any of the locked UTXOs so they're
					// free again.
					uErr := fundingState.unlockInputs(
						fundReq.ctx, f.cfg.ChainWallet,
					)
					if uErr != nil {
						log.Errorf("Unable to unlock "+
							"inputs: %v", uErr)
					}

					uErr = fundingState.unlockAssetInputs(
						fundReq.ctx, f.cfg.CoinSelector,
					)
					if uErr != nil {
						log.Errorf("Unable to unlock "+
							"asset inputs: %v",
							uErr)
					}

					fundReq.errChan <- err
					return
				}

				fundReq.respChan <- fundingTxid
			}()

		// The remote party has sent us some upfront proof for channel
		// asset inputs. We'll log this pending chan ID, then validate
		// the proofs included.
		case msg := <-f.msgs:
			// A new proof message has just come in, so we'll
			// extract the real proof wire message from the opaque
			// message.
			assetProofMgs, assetFunding, err := fundingFlows.fromMsg(
				msg,
			)
			if err != nil {
				fErr := fmt.Errorf("unable to convert msg to "+
					"proof: %w", err)
				f.cfg.ErrReporter.ReportError(
					funding.PendingChanID{}, fErr,
				)
				log.Error(fErr)
				continue
			}

			log.Infof("Recv'd new message: %T", assetProofMgs)

			tempPID := assetFunding.pid
			ctxb := context.Background()

			switch assetProof := assetProofMgs.(type) {
			// This is input proof, so we'll verify the challenge
			// witness, then store the proof.
			case *TxAssetInputProof:
				log.Infof("Validating input proof, prev_out=%v",
					assetProof.Proof.Val.OutPoint())

				// Next, we'll validate this proof to make sure
				// that the initiator is actually able to spend
				// these outputs in the funding transaction.
				_, err := assetProof.Proof.Val.Verify(
					ctxb, nil, f.cfg.HeaderVerifier,
					proof.DefaultMerkleVerifier,
					f.cfg.GroupVerifier,
				)
				if err != nil {
					fErr := fmt.Errorf("unable to verify "+
						"ownership proof: %w", err)
					f.cfg.ErrReporter.ReportError(
						tempPID, fErr,
					)
					log.Error(fErr)
					continue
				}

				// Now that we know the proof is valid, we'll
				// add it to the funding state.
				assetFunding.addProof(&assetProof.Proof.Val)

			// This is an output proof, so now we should be able to
			// verify the asset funding output with witness in
			// tact.
			case *TxAssetOutputProof:
				// First, we'll populate a map of all the
				// previous inputs. This is like the prev
				// output fetcher for Bitcoin.
				//prevAssets := make(commitment.InputSet)
				outputAsset := assetProof.AssetOutput.Val
				//witnesses := outputAsset.Witnesses()
				//prevID := witnesses[0].PrevID
				//
				//prevAssets[*prevID] = &outputAsset

				// With the inputs specified, we'll now attempt
				// to validate the state transition for the
				// asset funding output.

				// TODO(guggero): We can't actually verify the
				// asset here, because it's not signed yet...
				//engine, _ := vm.New(
				//	&outputAsset, nil, prevAssets,
				//)
				//if err := engine.Execute(); err != nil {
				//	fErr := fmt.Errorf("unable to verify "+
				//		"output proof: %w", err)
				//	f.cfg.ErrReporter.ReportError(
				//		tempPID, fErr,
				//	)
				//	log.Error(fErr)
				//	continue
				//}

				// If we reached this point, then the asset
				// output and all inputs are valid, so we'll
				// store the funding asset commitment.
				fundingCommitment, err := commitment.FromAssets(
					&outputAsset,
				)
				if err != nil {
					fErr := fmt.Errorf("unable to create "+
						"commitment: %v", err)
					log.Error(fErr)
					f.cfg.ErrReporter.ReportError(
						tempPID, fErr,
					)
					continue
				}

				assetFunding.fundingAssetCommitment = fundingCommitment

			// As the responder, we'll get this message after
			// we send AcceptChannel. This includes the suffix
			// proof for the funding output/transaction created
			// by the funding output.
			case *AssetFundingCreated:
				log.Infof("Storing funding output proof")

				// We'll just place this in the internal
				// funding state so we can derive the funding
				// desc when we need to.
				//
				// TODO(roasbeef): can validate
				// inclusion/exclusion proofs
				assetFunding.fundingOutputProofs = append(
					assetFunding.fundingOutputProofs,
					&assetProof.FundingOutput.Val,
				)
			}

		// A new request for a tapscript root has come across. If we
		// know this pid, then we already derived the root before we
		// sent OpenChannel, so we can just send that back to lnd
		case req := <-f.rootReqs:
			tempPID := req.tempPID

			// If there's no funding flow for this tempPID, then we
			// have nothing to return.
			fundingFlow, ok := fundingFlows[tempPID]
			if !ok {
				log.Infof("No funding flow for temp ID %x for "+
					"tapscript root request", tempPID[:])
				req.resp <- lfn.None[chainhash.Hash]()
				continue
			}

			fundingCommitment := fundingFlow.fundingAssetCommitment
			trimmedCommitment, err := tapsend.TrimSplitWitnesses(
				fundingCommitment,
			)
			if err != nil {
				fErr := fmt.Errorf("unable to anchor output "+
					"script: %w", err)
				f.cfg.ErrReporter.ReportError(tempPID, fErr)
				continue
			}

			tapscriptRoot := trimmedCommitment.TapscriptRoot(nil)
			log.Infof("Returning tapscript root: %v", tapscriptRoot)

			req.resp <- lfn.Some(tapscriptRoot)

		// A new request to map a pending channel ID to a complete aux
		// funding desc has just arrived. If we know of the pid, then
		// we'll assemble the full desc now. Otherwise, we return None.
		case req := <-f.bindFundingReqs:
			tempPID := req.tempPID

			// If there's no funding flow for this tempPID, then we
			// have nothing to return.
			fundingFlow, ok := fundingFlows[tempPID]
			if !ok {
				log.Infof("No funding flow for temp ID %x for "+
					"bind funding request", tempPID[:])
				req.resp <- lfn.None[lnwallet.AuxFundingDesc]()
				continue
			}

			// TODO(roasbeef): result type here?

			fundingDesc, err := fundingFlow.toAuxFundingDesc(
				f.cfg.ChainParams, req,
			)
			if err != nil {
				fErr := fmt.Errorf("unable to create aux funding "+
					"desc: %w", err)
				f.cfg.ErrReporter.ReportError(tempPID, fErr)
				continue
			}

			log.Infof("Returning funding desc: %v", spew.Sdump(fundingDesc))

			req.resp <- lfn.Some(*fundingDesc)

		case <-f.Quit:
			return
		}
	}
}

// FundReq is a message that's sent to the funding controller to request a new
// asset channel funding.
type FundReq struct {
	// PeerPub is the public key of the peer that we're funding a channel
	// with.
	//
	// TODO(roasbeef): also need p2p address?
	PeerPub btcec.PublicKey

	// AssetID is the asset that we're funding the channel with.
	AssetID asset.ID

	// Amt is the amount of the asset that we're funding the channel with.
	//
	// TODO(roasbeef) implicitly DummyAmtSats?
	Amt uint64

	// FeeRate is the fee rate that we'll use to fund the channel.
	FeeRate chainfee.SatPerVByte

	ctx      context.Context
	respChan chan *chainhash.Hash
	errChan  chan error
}

// FundChannel attempts to fund a new channel with the backing lnd node based
// on the passed funding request. If successful, the TXID of the funding
// transaction is returned.
func (f *FundingController) FundChannel(ctx context.Context,
	req FundReq) (*chainhash.Hash, error) {

	req.ctx = ctx
	req.respChan = make(chan *chainhash.Hash, 1)
	req.errChan = make(chan error, 1)

	if !fn.SendOrQuit(f.newFundingReqs, &req, f.Quit) {
		return nil, fmt.Errorf("funding controller is shutting down")
	}

	return fn.RecvResp(req.respChan, req.errChan, f.Quit)
}

// DescFromPendingChanID takes a pending channel ID, that may already be known
// due to prior custom channel messages, and maybe returns an aux funding desc
// which can be used to modify how a channel is funded.
func (f *FundingController) DescFromPendingChanID(pid funding.PendingChanID,
	openChan *channeldb.OpenChannel, localKeyRing,
	remoteKeyRing lnwallet.CommitmentKeyRing,
	initiator bool) (lfn.Option[lnwallet.AuxFundingDesc], error) {

	req := &bindFundingReq{
		tempPID:       pid,
		initiator:     initiator,
		openChan:      openChan,
		localKeyRing:  localKeyRing,
		remoteKeyRing: remoteKeyRing,
		resp:          make(chan lfn.Option[lnwallet.AuxFundingDesc], 1),
	}

	if !fn.SendOrQuit(f.bindFundingReqs, req, f.Quit) {
		return lfn.None[lnwallet.AuxFundingDesc](),
			fmt.Errorf("timeout when sending to funding controller")
	}

	resp, err := fn.RecvResp(req.resp, nil, f.Quit)
	if err != nil {
		return lfn.None[lnwallet.AuxFundingDesc](),
			fmt.Errorf("timeout when waiting for response: %w", err)
	}

	return resp, nil
}

// DeriveTapscriptRoot returns the tapscript root for the channel identified by
// the pid. If we don't have any information about the channel, we return None.
func (f *FundingController) DeriveTapscriptRoot(
	pid funding.PendingChanID) (lfn.Option[chainhash.Hash], error) {

	req := &assetRootReq{
		tempPID: pid,
		resp:    make(chan lfn.Option[chainhash.Hash], 1),
	}

	if !fn.SendOrQuit(f.rootReqs, req, f.Quit) {
		return lfn.None[chainhash.Hash](),
			fmt.Errorf("timeout when sending to funding controller")
	}

	resp, err := fn.RecvResp(req.resp, nil, f.Quit)
	if err != nil {
		return lfn.None[chainhash.Hash](),
			fmt.Errorf("timeout when waiting for response: %w", err)
	}

	return resp, nil
}

// Name returns the name of this endpoint. This MUST be unique across all
// registered endpoints.
func (f *FundingController) Name() string {
	return "taproot assets channel funding"
}

// CanHandle returns true if the target message can be routed to this endpoint.
func (f *FundingController) CanHandle(msg lnwire.Message) bool {
	switch msg := msg.(type) {
	case *lnwire.Custom:
		switch msg.MsgType() {
		case TxAssetInputProofType:
			fallthrough
		case TxAssetOutputProofType:
			fallthrough
		case AssetFundingCreatedType:
			return true
		}

	case *TxAssetInputProof:
		return true
	case *TxAssetOutputProof:
		return true
	case *AssetFundingCreated:
		return true
	}

	return false
}

// SendMessage handles the target message, and returns true if the message was
// able to be processed.
func (f *FundingController) SendMessage(msg lnwire.Message) bool {
	return fn.SendOrQuit(f.msgs, msg, f.Quit)
}

// TODO(roasbeef): will also want to supplement pendingchannels, etc

// TODO(roasbeef): try to protofsm it?

// A compile-time assertion to ensure FundingController meets the
// funding.AuxFundingController interface.
var _ funding.AuxFundingController = (*FundingController)(nil)
