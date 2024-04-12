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
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightningnetwork/lnd/funding"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/tlv"
)

const (
	// TxAssetMsgType...
	TxAssetMsgType lnwire.MessageType = 32769 // starts at 32768
)

// TxAssetProof...
type TxAssetProof struct {
	// TempChanID....
	TempChanID tlv.RecordT[tlv.TlvType0, funding.PendingChanID]

	// AssetID is the ID of the asset that this output is associated with.
	AssetID tlv.RecordT[tlv.TlvType1, asset.ID]

	// Amount is the amount of the asset that this output represents.
	Amount tlv.RecordT[tlv.TlvType2, uint64]

	// Proof is the last transition proof that proves this output was
	// committed to in the Bitcoin transaction that anchors this asset
	// output.
	//
	// TODO(roasbeef): will have a challenge witness proves, that sender is
	// able to do the state transition
	Proof tlv.RecordT[tlv.TlvType3, proof.Proof]

	// End is a boolean that indicates that this is the last message in the
	// series. After this, the receiver knows to attempt to compute the
	// final funding asset root.
	End tlv.RecordT[tlv.TlvType4, bool]
}

// MsgType returns the type of the message.
func (t *TxAssetProof) MsgType() lnwire.MessageType {
	return TxAssetMsgType
}

// Decode reads the bytes stream and converts it to the object.
func (t *TxAssetProof) Decode(r io.Reader, _ uint32) error {
	stream, err := tlv.NewStream(
		t.TempChanID.Record(),
		t.AssetID.Record(),
		t.Amount.Record(),
		t.Proof.Record(),
	)
	if err != nil {
		return err
	}

	return stream.Decode(r)
}

// Encode converts object to the bytes stream and write it into the
// write buffer.
func (t *TxAssetProof) Encode(w *bytes.Buffer, _ uint32) error {
	stream, err := tlv.NewStream(
		t.TempChanID.Record(),
		t.AssetID.Record(),
		t.Amount.Record(),
		t.Proof.Record(),
	)
	if err != nil {
		return err
	}

	return stream.Encode(w)
}

// ErrorReporter...
type ErrorReporter interface {
	// ReportError reports an error that occurred during the funding
	// process.
	ReportError(pid funding.PendingChanID, err error)
}

// FundingControllerCfg...
type FundingControllerCfg struct {
	// HeaderVerifier...
	HeaderVerifier proof.HeaderVerifier

	// GroupVerifier...
	GroupVerifier proof.GroupVerifier

	// ErrReporter...
	ErrReporter ErrorReporter

	// TODO(roasbeef): report error similar to other?
}

// fundingReq...
type fundingReq struct {
	initiator bool

	tempPID funding.PendingChanID

	resp chan fn.Option[lnwallet.AuxFundingDesc]
}

// FundingController...
type FundingController struct {
	started atomic.Bool
	stopped atomic.Bool

	cfg FundingControllerCfg

	msgs chan lnwire.Message

	fundingReqs chan *fundingReq

	quit chan struct{}
	wg   sync.WaitGroup
}

// TODO(roasbeef): will use ProveAssetOwnership

// NewFundingController...
func NewFundingController() *FundingController {
	return &FundingController{
		msgs:        make(chan lnwire.Message, 10),
		fundingReqs: make(chan *fundingReq, 10),
		quit:        make(chan struct{}),
	}
}

// Start...
func (f *FundingController) Start() error {
	if !f.started.CompareAndSwap(false, true) {
		return nil
	}

	f.wg.Add(1)
	go f.chanFunder()

	return nil
}

// Stop...
func (f *FundingController) Stop() error {
	if !f.started.CompareAndSwap(true, false) {
		return nil
	}

	return nil
}

func newPendingChanID() (funding.PendingChanID, error) {
	var id funding.PendingChanID
	if _, err := io.ReadFull(crand.Reader, id[:]); err != nil {
		return id, err
	}

	return id, nil
}

// pendingAssetFunding...
type pendingAssetFunding struct {
	pid funding.PendingChanID

	initiator bool

	// TODO(roasbeef): should be the new Either identifier?
	assetID asset.ID

	amt uint64

	proofs []proof.Proof

	fundingRoot *mssmt.BranchNode
}

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

// chanFunder...
func (f *FundingController) chanFunder() {
	defer f.wg.Done()

	fundingFlows := make(map[funding.PendingChanID]*pendingAssetFunding)

	for {
		select {

		// A new funding message has just come in, we'll log this
		// pending chan ID, then validate the proofs included.
		case msg := <-f.msgs:
			// A new proof message has just come in, so we'll
			// extract the real proof wire message from the opaque
			// message.
			assetProof, _ := msgToAssetProof(msg)

			assetID := assetProof.AssetID.Val
			tempPID := assetProof.TempChanID.Val

			// Next, we'll see if this is already part of an active
			// funding flow. If not, then we'll make a new one to
			// accumulate this new proof.
			assetFunding, ok := fundingFlows[tempPID]
			if !ok {
				assetFunding = &pendingAssetFunding{
					pid:     assetProof.TempChanID.Val,
					assetID: assetID,
					amt:     assetProof.Amount.Val,
				}
			}

			ctxb := context.Background()

			// TODO(rosabeef): verify that has challenge witness
			// before?

			// TODO(roasbeef): pass thru context as well?

			// Next, we'll validate this proof to make sure that
			// the initiator is actually able to spend these
			// outputs in the funding transaction.
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
			assetFunding.proofs = append(
				assetFunding.proofs, assetProof.Proof.Val,
			)

			// If this is the final funding proof, then we're done
			// here, and we can assemble the funding asset root
			// that we'll use in the next phase.
			if !assetProof.End.Val {
				continue
			}

			fundingTree := mssmt.NewCompactedTree(
				mssmt.NewDefaultStore(),
			)
			for _, proof := range assetFunding.proofs {
				assetInput := proof.Asset

				assetKey := assetInput.AssetCommitmentKey()
				assetLeaf, err := assetInput.Leaf()
				if err != nil {
					fmt.Println(err)
				}

				_, err = fundingTree.Insert(
					ctxb, assetKey, assetLeaf,
				)
				if err != nil {
					fmt.Println(err)
				}
			}

			// With all the items inserted, we can now compute the
			// root that'll be used to identity this input set.
			fundingRoot, err := fundingTree.Root(ctxb)
			if err != nil {
				fmt.Println(err)
			}

			assetFunding.fundingRoot = fundingRoot

		// A new request to map a pending channel ID to a complete aux
		// funding desc has just arrived. If we know of the pid, then
		// we'll assemble the full desc now. Otherwise, we return None.
		case req := <-f.fundingReqs:
			tempPID := req.tempPID

			fundingFlow, ok := fundingFlows[tempPID]
			if !ok {
				req.resp <- fn.None[lnwallet.AuxFundingDesc]()
			}

			var fundingDesc lnwallet.AuxFundingDesc

			// First, we'll map all the assets into asset outputs
			// that'll be stored in the open channel struct on the
			// lnd side.
			assetOutputs := fn.Map(fundingFlow.proofs, func(p proof.Proof) *AssetOutput {
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

			// With all the outputs assembled, we'll now map that
			// to the open channel wrapper that'll go in the set of
			// TLV blobs.
			openChanDesc := NewOpenChannel(assetOutputs)

			// Now we'll encode the 3 TLV blobs that lnd will
			// store: the main one for the funding details, and
			// then the blobs for the local and remote commitment
			var fundB bytes.Buffer
			_ = openChanDesc.Encode(&fundB)
			fundingDesc.CustomFundingBlob = fundB.Bytes()

			// TODO(roasbeef): need to know if we're the initiator
			// or not?

			var localCommitB, remoteCommitB bytes.Buffer
			commitAssets := assetOutputListRecord{
				outputs: assetOutputs,
			}

			localCommit := Commitment{
				LocalAssets: tlv.NewRecordT[tlv.TlvType0](
					commitAssets,
				),
			}

			localCommit.Encode(&localCommitB)
			fundingDesc.CustomLocalCommitBlob = localCommitB.Bytes()

			remoteCommit := Commitment{
				RemoteAssets: tlv.NewRecordT[tlv.TlvType1](
					commitAssets,
				),
			}

			remoteCommit.Encode(&remoteCommitB)
			fundingDesc.CustomRemoteCommitBlob = remoteCommitB.Bytes()

			// With all the blobs set, we'll now derive the
			// tapscsript root that will commit to all the assets
			// in the channel.
			//
			// TODO(roasbeef): assumes no group key
			fundingAsset := assetOutputs[0].Proof.Val.Asset.Copy()
			fundingAsset.Amount = fundingFlow.amt
			fundingAsset.SplitCommitmentRoot = nil
			fundingAsset.PrevWitnesses = fn.Map(fundingFlow.proofs, func(p proof.Proof) asset.Witness {
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

			fundingScriptTree := NewFundingScriptTree()

			fundingAsset.ScriptKey = asset.ScriptKey{
				PubKey: fundingScriptTree.InternalKey,
			}

			req.resp <- fn.Some(fundingDesc)

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

	req := &fundingReq{
		tempPID:   pid,
		initiator: initiator,
		resp:      make(chan fn.Option[lnwallet.AuxFundingDesc], 1),
	}

	if !fn.SendOrQuit(f.fundingReqs, req, f.quit) {
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
