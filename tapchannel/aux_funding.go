package tapchannel

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightningnetwork/lnd/funding"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/tlv"
)

// ErrorReporter is used to report an error back to the caller and/or peer that
// we're communiating with.
type ErrorReporter interface {
	// ReportError reports an error that occurred during the funding
	// process.
	ReportError(pid funding.PendingChanID, err error)
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
}

// bindFundingReq is a request to bind a pending channel ID to a complete aux
// funding desc. This is used by the initiator+responder after the pre funding messages
// and interaction is compelte.
type bindFundingReq struct {
	initiator bool

	tempPID funding.PendingChanID

	resp chan fn.Option[lnwallet.AuxFundingDesc]
}

// FundingController is used to drive TAP aware channel funding using a backing
// lnd node and an active connection to a tapd instance.
type FundingController struct {
	started atomic.Bool
	stopped atomic.Bool

	cfg FundingControllerCfg

	msgs chan lnwire.Message

	bindFundingReqs chan *bindFundingReq

	quit chan struct{}
	wg   sync.WaitGroup
}

// TODO(roasbeef): will use ProveAssetOwnership

// NewFundingController creates a new instance of the FundingController.
func NewFundingController(cfg FundingControllerCfg) *FundingController {
	return &FundingController{
		cfg:             cfg,
		msgs:            make(chan lnwire.Message, 10),
		bindFundingReqs: make(chan *bindFundingReq, 10),
		quit:            make(chan struct{}),
	}
}

// Start starts the funding controller.
func (f *FundingController) Start() error {
	if !f.started.CompareAndSwap(false, true) {
		return nil
	}

	f.wg.Add(1)
	go f.chanFunder()

	return nil
}

// Stop stops the funding controller.
func (f *FundingController) Stop() error {
	if !f.started.CompareAndSwap(true, false) {
		return nil
	}

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
// pending asset channel funding flow.o
type pendingAssetFunding struct {
	pid funding.PendingChanID

	initiator bool

	// TODO(roasbeef): should be the new Either identifier?
	assetID asset.ID

	amt uint64

	proofs []proof.Proof

	fundingRoot *mssmt.BranchNode
}

// addProof adds a new proof to the set of proofs that'll be used to fund the
// new channel.
func (p *pendingAssetFunding) addProof(proof proof.Proof) {
	p.proofs = append(p.proofs, proof)
}

// assetRootFromInputs computes the asset root from the set of inputs provided.
// This'll be used to idetnify the set of assets that'll be used as funding
// inputs into the channel.
func assetRootFromInputs(inputs []proof.Proof) (*mssmt.BranchNode, error) {
	ctxb := context.Background()

	// Insert all the assets into a new SMT that'll commit to all the
	// assets we plan to use as input to funding.
	fundingTree := mssmt.NewCompactedTree(mssmt.NewDefaultStore())
	for _, proof := range inputs {
		assetInput := proof.Asset

		assetKey := assetInput.AssetCommitmentKey()
		assetLeaf, err := assetInput.Leaf()
		if err != nil {
			return nil, err
		}

		_, err = fundingTree.Insert(ctxb, assetKey, assetLeaf)
		if err != nil {
			return nil, err
		}
	}

	// With all the items inserted, we can now compute the root that'll be
	// used to identity this input set.
	return fundingTree.Root(context.Background())
}

// bindFundingRoot binds the funding root to the pending channel ID. Once
// bound, the pre funding process is complete, and as the responder, we're now
// ready for the next phase of the funding flow.
func (p *pendingAssetFunding) bindFundingRoot() error {
	fundingRoot, err := assetRootFromInputs(p.proofs)
	if err != nil {
		return fmt.Errorf("error computing asset root: %v", err)
	}

	p.fundingRoot = fundingRoot

	return nil
}

// assetOutputs returns the set of asset outputs that'll be used to fund the
// new asset channel.
func (p *pendingAssetFunding) assetOutputs() []*AssetOutput {
	return fn.Map(p.proofs, func(p proof.Proof) *AssetOutput {
		return &AssetOutput{
			AssetID: tlv.NewRecordT[tlv.TlvType0](
				p.Asset.ID(),
			),
			Amount: tlv.NewPrimitiveRecord[tlv.TlvType1](
				p.Asset.Amount,
			),
			Proof: tlv.NewRecordT[tlv.TlvType2](p),
		}
	})
}

// newCommitBlob creates a new commitment blob that'll be stored in the channel
// state for the specified party.
func newCommitBlob(chanAssets assetOutputListRecord,
	local bool) ([]byte, error) {

	var commit Commitment
	if local {
		commit.LocalAssets = tlv.NewRecordT[tlv.TlvType0](
			chanAssets,
		)
	} else {
		commit.RemoteAssets = tlv.NewRecordT[tlv.TlvType1](
			chanAssets,
		)
	}

	var b bytes.Buffer
	err := commit.Encode(&b)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// toAuxFundingDesc converts the pending asset funding into a full aux funding
// desc. This is the final step in the modified funding process, as after this,
// both sides are able to construct the funding output, and will be able to
// store the appropriate funding blobs.
func (p *pendingAssetFunding) toAuxFundingDesc(initiator bool,
) (*lnwallet.AuxFundingDesc, error) {

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

	commitAssets := assetOutputListRecord{
		outputs: assetOutputs,
	}

	// Encode the commitment blobs for both the local and remote party.
	// This will be the information for the very first state (state 0).
	var err error
	fundingDesc.CustomLocalCommitBlob, err = newCommitBlob(
		commitAssets, p.initiator,
	)
	if err != nil {
		return nil, err
	}
	fundingDesc.CustomRemoteCommitBlob, err = newCommitBlob(
		commitAssets, !p.initiator,
	)
	if err != nil {
		return nil, err
	}

	// Create the TAP level tapscript tree for the funding output. This'll
	// be a simply OP_TRUE output, meaning we need no extra signatures for
	// a valid commitment.
	fundingScriptTree := NewFundingScriptTree()

	// With all the blobs set, we'll now derive the tapscsript root that
	// will commit to all the assets in the channel.
	//
	// TODO(roasbeef): assumes no group key
	fundingAsset := assetOutputs[0].Proof.Val.Asset.Copy()
	fundingAsset.Amount = p.amt
	fundingAsset.SplitCommitmentRoot = nil

	// TODO(roasbeef): need to sign all inputs
	fundingWitness := fn.Map(p.proofs, func(p proof.Proof) asset.Witness {
		return asset.Witness{
			PrevID: &asset.PrevID{
				OutPoint: p.OutPoint(),
				ID:       p.Asset.ID(),
				ScriptKey: asset.ToSerialized(
					p.Asset.ScriptKey.PubKey,
				),
			},
		}
	})
	fundingAsset.PrevWitnesses = fundingWitness

	// The output script key for the funding output will be just the
	// OP_TRUE script-only output key.
	fundingAsset.ScriptKey = asset.ScriptKey{
		PubKey: fundingScriptTree.TaprootKey,
	}

	// Finally, we'll derive the tapscript root that'll commit to the new
	// funding asset output we created above.
	tapCommitment, err := commitment.FromAssets(fundingAsset)
	if err != nil {
		return nil, err
	}
	fundingDesc.TapscriptRoot = tapCommitment.TapscriptRoot(nil)

	return &fundingDesc, nil
}

// msgToAssetProof converts a wire message to a TxAssetProof.
func msgToAssetProof(msg lnwire.Message) (*TxAssetProof, error) {
	switch msg := msg.(type) {
	case *lnwire.Custom:
		var assetProof TxAssetProof
		err := assetProof.Decode(bytes.NewReader(msg.Data), 0)
		if err != nil {
			return nil, err
		}

		return &assetProof, nil

	case *TxAssetProof:
		return msg, nil

	default:
		panic("u wot m8?")
	}
}

// TODO(roasbeef): interface also needs method to pass in amt+asset ID, then
// send out proofs to other side

// fundingFlowIndex is a map from pending channel ID to the current state of
// the funding flow.
type fundingFlowIndex map[funding.PendingChanID]*pendingAssetFunding

// fromMsg attempts to match an incoming message to the pending funding flow,
// and extracts the asset proof from the message.
func (f *fundingFlowIndex) fromMsg(msg lnwire.Message) (*TxAssetProof, *pendingAssetFunding) {
	assetProof, _ := msgToAssetProof(msg)

	assetID := assetProof.AssetID.Val
	tempPID := assetProof.TempChanID.Val

	// Next, we'll see if this is already part of an active
	// funding flow. If not, then we'll make a new one to
	// accumulate this new proof.
	assetFunding, ok := (*f)[tempPID]
	if !ok {
		assetFunding = &pendingAssetFunding{
			pid:     assetProof.TempChanID.Val,
			assetID: assetID,
			amt:     assetProof.Amount.Val,
		}
	}

	return assetProof, assetFunding
}

// chanFunder is the main event loop that controls the asset specific portions
// of the funding request.
func (f *FundingController) chanFunder() {
	defer f.wg.Done()

	fundingFlows := make(fundingFlowIndex)

	for {
		select {

		// A new funding message has just come in, we'll log this
		// pending chan ID, then validate the proofs included.
		case msg := <-f.msgs:
			// A new proof message has just come in, so we'll
			// extract the real proof wire message from the opaque
			// message.
			assetProof, assetFunding := fundingFlows.fromMsg(msg)

			tempPID := assetProof.TempChanID.Val

			// TODO(rosabeef): verify that has challenge witness
			// before?

			// Next, we'll validate this proof to make sure that
			// the initiator is actually able to spend these
			// outputs in the funding transaction.
			ctxb := context.Background()
			_, err := assetProof.Proof.Val.Verify(
				ctxb, nil, f.cfg.HeaderVerifier,
				proof.DefaultMerkleVerifier,
				f.cfg.GroupVerifier,
			)
			if err != nil {
				fErr := fmt.Errorf("unable to verify proof: "+
					"%w", err)
				f.cfg.ErrReporter.ReportError(tempPID, fErr)
				continue
			}

			// Now that we know the proof is valid, we'll add it to
			// the funding state.
			assetFunding.addProof(assetProof.Proof.Val)

			// If this is the final funding proof, then we're done
			// here, and we can assemble the funding asset root
			// that we'll use in the next phase.
			if !assetProof.End.Val {
				continue
			}

			if err := assetFunding.bindFundingRoot(); err != nil {
				fErr := fmt.Errorf("unable to bind funding root: "+
					"%w", err)
				f.cfg.ErrReporter.ReportError(tempPID, fErr)
				continue
			}

		// A new request to map a pending channel ID to a complete aux
		// funding desc has just arrived. If we know of the pid, then
		// we'll assemble the full desc now. Otherwise, we return None.
		case req := <-f.bindFundingReqs:
			tempPID := req.tempPID

			// If there's no funding flow for this tempPID, then we
			// have nothing to return.
			fundingFlow, ok := fundingFlows[tempPID]
			if !ok {
				req.resp <- fn.None[lnwallet.AuxFundingDesc]()
			}

			// TODO(roasbeef): result type here?

			fundingDesc, err := fundingFlow.toAuxFundingDesc(
				req.initiator,
			)
			if err != nil {
				fErr := fmt.Errorf("unable to create aux funding "+
					"desc: %w", err)
				f.cfg.ErrReporter.ReportError(tempPID, fErr)
				continue
			}

			req.resp <- fn.Some(*fundingDesc)

		case <-f.quit:
			return
		}
	}
}

// FundChannel...
func (f *FundingController) FundChannel(peerPub btcec.PublicKey,
	assetID asset.ID, amt uint64) error {

	return nil
}

// DescPendingChanID takes a pending channel ID, that may already be known due
// to prior custom channel messages, and maybe returns an aux funding desc
// which can be used to modify how a channel is funded.
//
// TODO(roasbeef): erorr on validation if fail due to invalid root match?
func (f *FundingController) DescFromPendingChanID(pid funding.PendingChanID,
	initiator bool) fn.Option[lnwallet.AuxFundingDesc] {

	req := &bindFundingReq{
		tempPID:   pid,
		initiator: initiator,
		resp:      make(chan fn.Option[lnwallet.AuxFundingDesc], 1),
	}

	if !fn.SendOrQuit(f.bindFundingReqs, req, f.quit) {
		return fn.None[lnwallet.AuxFundingDesc]()
	}

	resp, _ := fn.RecvResp(req.resp, nil, f.quit)
	return resp
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
		return msg.MsgType() == TxAssetMsgType

	case *TxAssetProof:
		return true
	}

	return false
}

// SendMessage handles the target message, and returns true if the message was
// able to be processed.
func (f *FundingController) SendMessage(msg lnwire.Message) bool {
	return fn.SendOrQuit(f.msgs, msg, f.quit)
}

// TODO(roasbeef): will also want to supplement pendingchannels, etc

// TODO(roasbeef): try to protofsm it?
