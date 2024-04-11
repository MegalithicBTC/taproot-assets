package tapchannel

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
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
	Proof tlv.RecordT[tlv.TlvType3, proof.Proof]
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

// FundingController...
type FundingController struct {
	started atomic.Bool
	stopped atomic.Bool

	msgs chan lnwire.Message

	fundingReqs chan funding.PendingChanID

	// pendingAssetFunding lnutils.SyncMap[asset.ID, funding.PendingChanID]

	quit chan struct{}
	wg   sync.WaitGroup
}

// NewFundingController...
func NewFundingController() *FundingController {
	return &FundingController{
		msgs:        make(chan lnwire.Message, 10),
		fundingReqs: make(chan funding.PendingChanID, 10),
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

type pendingAssetFunding struct {
	pid funding.PendingChanID

	assetID asset.ID

	amt uint64

	proofs map[asset.ID]proof.Proof
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

	activeFundingFlows := make(map[funding.PendingChanID]pendingAssetFunding)

	for {
		select {

		// A new funding message has just come in, we'll log this
		// pending chan ID, then validate the proofs included.
		case msg := <-f.msgs:
			assetProof, _ := msgToAssetProof(msg)

			assetID := assetProof.AssetID.Val

			assetFunding, ok := activeFundingFlows[assetProof.TempChanID.Val]
			if !ok {
				assetFunding = pendingAssetFunding{
					pid:     assetProof.TempChanID.Val,
					assetID: assetID,
					amt:     assetProof.Amount.Val,
					proofs:  make(map[asset.ID]proof.Proof),
				}
			}

			assetFunding.proofs[assetID] = assetProof.Proof.Val

			// TODO(roasbeef): extend to be able to verify proof

			_, err := assetProof.Proof.Val.Verify(
				context.Background(), nil, nil, nil, nil,
			)
			if err != nil {
				fmt.Println("proof verification failed: ", err)
			}

		case fundingReq := <-f.fundingReqs:
			fmt.Println(fundingReq)

		case <-f.quit:
			return
		}
	}
}

// DescPendingChanID takes a pending channel ID, that may already be known due
// to prior custom channel messages, and maybe returns an aux funding desc
// which can be used to modify how a channel is funded.
//
// TODO(roasbeef): erorr on validation if fail due to invalid root match?
func (f *FundingController) DescFromPendingChanID(pid funding.PendingChanID,
) fn.Option[lnwallet.AuxFundingDesc] {

	return fn.None[lnwallet.AuxFundingDesc]()
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
