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

// AssetFundingMsg is an interface that represents a message that is sent
// during the asset funding process.
type AssetFundingMsg interface {
	lnwire.Message

	FundingAssetID() asset.ID

	PendingChanID() funding.PendingChanID

	Amt() uint64
}

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
	Proof tlv.RecordT[tlv.TlvType3, proof.Proof]
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

// PendingChanID returns the temporary channel ID that was assigned to the
// channel.
func (t *TxAssetInputProof) PendingChanID() funding.PendingChanID {
	return t.TempChanID.Val
}

// FundingAssetID returns the asset ID of the underlying asset.
func (t *TxAssetInputProof) FundingAssetID() asset.ID {
	return t.AssetID.Val
}

// Amt returns the amount of the asset that this output represents.
func (t *TxAssetInputProof) Amt() uint64 {
	return t.Amount.Val
}

// A compile time check to ensure TxAssetInputProof implements the
// AssetFundingMsg interface.
var _ AssetFundingMsg = (*TxAssetInputProof)(nil)

// TxAssetOutputProof is sent by the initiator of the funding request *after*
// the inputs proofs. The proof contained in this message is the final signed
// asset funding output. Along with the input proofs, then the responder can
// verify the asset funding output witnesses in full.
type TxAssetOutputProof struct {
	// TempChanID is the temporary channel ID that was assigned to the
	// channel.
	TempChanID tlv.RecordT[tlv.TlvType0, funding.PendingChanID]

	// AssetOutput is one of the funding UTXOs that'll be used in channel
	// funding.
	AssetOutput tlv.RecordT[tlv.TlvType1, asset.Asset]

	// TODO(roasbeef): end here after multi-asset?
}

// MsgType returns the type of the message.
func (t *TxAssetOutputProof) MsgType() lnwire.MessageType {
	return TxAssetInputProofType
}

// Decode reads the bytes stream and converts it to the object.
func (t *TxAssetOutputProof) Decode(r io.Reader, _ uint32) error {
	stream, err := tlv.NewStream(
		t.TempChanID.Record(),
		t.AssetOutput.Record(),
	)
	if err != nil {
		return err
	}

	return stream.Decode(r)
}

// Encode converts object to the bytes stream and write it into the write
// buffer.
func (t *TxAssetOutputProof) Encode(w *bytes.Buffer, _ uint32) error {
	stream, err := tlv.NewStream(
		t.TempChanID.Record(),
		t.AssetOutput.Record(),
	)
	if err != nil {
		return err
	}

	return stream.Encode(w)
}

// PendingChanID returns the temporary channel ID that was assigned to the
// channel.
func (t *TxAssetOutputProof) PendingChanID() funding.PendingChanID {
	return t.TempChanID.Val
}

// FundingAssetID returns the asset ID of the underlying asset.
func (t *TxAssetOutputProof) FundingAssetID() asset.ID {
	return t.AssetOutput.Val.ID()
}

// Amt returns the amount of the asset that this output represents.
func (t *TxAssetOutputProof) Amt() uint64 {
	return t.AssetOutput.Val.Amount
}

// A compile time check to ensure TxAssetOutputProof implements the
// AssetFundingMsg interface.
var _ AssetFundingMsg = (*TxAssetOutputProof)(nil)
