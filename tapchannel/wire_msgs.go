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

// RecordSlice is a generic type that can be used to encode a slice of records.
// It uses a var int prefix of the number of records.
type RecordSlice[T tlv.RecordProducer] struct {
	records []T
}

func eRecordSlice[T tlv.RecordProducer](w *bytes.Buffer, recordPs []T, buf *[8]byte) error {
	if err := tlv.WriteVarInt(w, uint64(len(recordPs)), buf); err != nil {
		return err
	}

	for _, recordP := range recordPs {
		record := recordP.Record()
		if err := record.Encode(w); err != nil {
			return err
		}
	}

	return nil
}

func dRecordSlice[T tlv.RecordProducer](r io.Reader, recordPs []T, buf *[8]byte) error {
	numRecords, err := tlv.ReadVarInt(r, buf)
	if err != nil {
		return err
	}

	for i := 0; i < int(numRecords); i++ {
		var l uint64
		record := recordPs[i].Record()
		if err := record.Decode(r, l); err != nil {
			return err
		}
	}

	return nil
}

// AssetFundingCreated is sent by the initiator of the funding flow after
// they've able to fully finalize the funding transaction. This message will be
// sent before the normal funding_created message.
type AssetFundingCreated struct {
	// TempChanID is the temporary channel ID that was assigned to the
	// channel.
	TempChanID tlv.RecordT[tlv.TlvType0, funding.PendingChanID]

	// FundingOutput are the completed set of funding output proofs. The
	// remote party will use the transition (suffix) proofs encoded in the
	// funding output to be able to create the aux funding+commitment
	// blobs.
	//
	// TODO(roasbeef): generalize for multiple, needed for multi-asset,
	// group key, etc.
	FundingOutput tlv.RecordT[tlv.TlvType1, proof.Proof]
}

// MsgType returns the type of the message.
func (a *AssetFundingCreated) MsgType() lnwire.MessageType {
	return TxAssetInputProofType
}

// Decode reads the bytes stream and converts it to the object.
func (t *AssetFundingCreated) Decode(r io.Reader, _ uint32) error {
	stream, err := tlv.NewStream(
		t.TempChanID.Record(),
		t.FundingOutput.Record(),
	)
	if err != nil {
		return err
	}

	return stream.Decode(r)
}

// Encode converts object to the bytes stream and write it into the
// write buffer.
func (t *AssetFundingCreated) Encode(w *bytes.Buffer, _ uint32) error {
	stream, err := tlv.NewStream(
		t.TempChanID.Record(),
		t.FundingOutput.Record(),
	)
	if err != nil {
		return err
	}

	return stream.Encode(w)
}

// PendingChanID returns the temporary channel ID that was assigned to the
// channel.
func (t *AssetFundingCreated) PendingChanID() funding.PendingChanID {
	return t.TempChanID.Val
}

// FundingAssetID returns the asset ID of the underlying asset.
func (t *AssetFundingCreated) FundingAssetID() asset.ID {
	return t.FundingOutput.Val.Asset.ID()
}

// Amt returns the amount of the asset that this output represents.
func (t *AssetFundingCreated) Amt() uint64 {
	return t.FundingOutput.Val.Asset.Amount
}
