package tapchannel

import (
	"bytes"
	"io"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightningnetwork/lnd/funding"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/tlv"
)

const (
	// TxAssetInputProofType is the message type of the TxAssetInput
	// message.
	TxAssetInputProofType lnwire.MessageType = 32769 // starts at 32768

	// TxAssetOutputProofType is the message type of the TxAssetOutput
	// message.
	TxAssetOutputProofType lnwire.MessageType = 32770

	// AssetFundingCreatedType is the message type of the
	// AssetFundingCreated message.
	AssetFundingCreatedType lnwire.MessageType = 32771
)

// TxAssetInputProof is sent by the initiator of a channel funding request to prove
// to the upcoming responder that they are the owner of an asset input.
//
// TODO(roasbeef): fix challenge thing, use temp chan ID as the challenge?
type TxAssetInputProof struct {
	// TempChanID is the temporary channel ID that was assigned to the
	// channel.
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
func (t *TxAssetInputProof) MsgType() lnwire.MessageType {
	return TxAssetInputProofType
}

// Decode reads the bytes stream and converts it to the object.
func (t *TxAssetInputProof) Decode(r io.Reader, _ uint32) error {
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
func (t *TxAssetInputProof) Encode(w *bytes.Buffer, _ uint32) error {
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
