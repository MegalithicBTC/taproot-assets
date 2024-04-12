package tapchannel

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/txscript"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/proof"
	lfn "github.com/lightningnetwork/lnd/fn"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/tlv"
)

const (
	// MaxNumOutputs is the maximum number of asset outputs that are allowed
	// in a single record. This mainly affects the maximum number of asset
	// UTXOs that can reside within a single commitment. This number should
	// in practice be very small (probably close to 1), as all outputs must
	// be from the same asset group but from different tranches to be
	// encoded as an individual record.
	MaxNumOutputs = 2048

	// MaxNumHTLCs is the maximum number of HTLCs that are allowed in a
	// single record.
	MaxNumHTLCs = input.MaxHTLCNumber

	// OutputMaxSize is the maximum size of an asset output record. This is
	// the sum of the maximum sizes of the fields in the record.
	OutputMaxSize = 32 + 8 + proof.FileMaxProofSizeBytes
)

var (
	// ErrListInvalid is the error that's returned when a list of encoded
	// entries is invalid.
	ErrListInvalid = errors.New("encoded list is invalid")
)

// OpenChannel is a record that represents the capacity information related to
// a commitment. This entails all the (asset_id, amount, proof) tuples and other
// information that we may need to be able to sign the TAP portion of the
// commitment transaction.
type OpenChannel struct {
	// FundedAssets is a list of asset outputs that was committed to the
	// funding output of a commitment.
	FundedAssets tlv.RecordT[tlv.TlvType0, assetOutputListRecord]
}

// NewOpenChannel creates a new OpenChannel record with the given funded assets.
func NewOpenChannel(fundedAssets []*AssetOutput) *OpenChannel {
	return &OpenChannel{
		FundedAssets: tlv.NewRecordT[tlv.TlvType0](
			assetOutputListRecord{
				outputs: fundedAssets,
			},
		),
	}
}

// Assets returns the list of asset outputs that are committed to in the
// OpenChannel struct.
func (o *OpenChannel) Assets() []*AssetOutput {
	return o.FundedAssets.Val.outputs
}

// records returns the records that make up the OpenChannel.
func (o *OpenChannel) records() []tlv.Record {
	return []tlv.Record{
		o.FundedAssets.Record(),
	}
}

// Encode serializes the OpenChannel to the given io.Writer.
func (o *OpenChannel) Encode(w io.Writer) error {
	tlvRecords := o.records()

	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(tlvRecords...)
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the OpenChannel from the given io.Reader.
func (o *OpenChannel) Decode(r io.Reader) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(o.records()...)
	if err != nil {
		return err
	}

	return tlvStream.Decode(r)
}

// DecodeOpenChannel deserializes an OpenChannel from the given blob.
func DecodeOpenChannel(blob tlv.Blob) (*OpenChannel, error) {
	var o OpenChannel
	err := o.Decode(bytes.NewReader(blob))
	if err != nil {
		return nil, err
	}

	return &o, nil
}

// AuxLeaves is a record that represents the auxiliary leaves that correspond to
// a commitment.
type AuxLeaves struct {
	// LocalAuxLeaf is the auxiliary leaf that corresponds to the local
	// commitment.
	LocalAuxLeaf tlv.OptionalRecordT[tlv.TlvType0, tapLeafRecord]

	// RemoteAuxLeaf is the auxiliary leaf that corresponds to the remote
	// commitment.
	RemoteAuxLeaf tlv.OptionalRecordT[tlv.TlvType1, tapLeafRecord]

	// OutgoingHtlcLeaves is a map of HTLC indices to auxiliary leaves that
	// correspond to the outgoing HTLCs.
	OutgoingHtlcLeaves tlv.RecordT[tlv.TlvType2, htlcAuxLeafMapRecord]

	// IncomingHtlcLeaves is a map of HTLC indices to auxiliary leaves that
	// correspond to the incoming HTLCs.
	IncomingHtlcLeaves tlv.RecordT[tlv.TlvType3, htlcAuxLeafMapRecord]
}

// NewAuxLeaves creates a new AuxLeaves record with the given local, remote,
// incoming, and outgoing auxiliary leaves.
func NewAuxLeaves(local, remote input.AuxTapLeaf, outgoing,
	incoming input.AuxTapLeaves) AuxLeaves {

	leaves := AuxLeaves{
		OutgoingHtlcLeaves: tlv.NewRecordT[tlv.TlvType2](
			newHtlcAuxLeafMapRecord(outgoing),
		),
		IncomingHtlcLeaves: tlv.NewRecordT[tlv.TlvType3](
			newHtlcAuxLeafMapRecord(incoming),
		),
	}

	local.WhenSome(func(leaf txscript.TapLeaf) {
		leaves.LocalAuxLeaf = tlv.SomeRecordT[tlv.TlvType0](
			tlv.NewRecordT[tlv.TlvType0](tapLeafRecord{
				leaf: leaf,
			}),
		)
	})

	remote.WhenSome(func(leaf txscript.TapLeaf) {
		leaves.RemoteAuxLeaf = tlv.SomeRecordT[tlv.TlvType1](
			tlv.NewRecordT[tlv.TlvType1](tapLeafRecord{
				leaf: leaf,
			}),
		)
	})

	return leaves
}

// DecodeAuxLeaves deserializes an OpenChannel from the given blob.
func DecodeAuxLeaves(blob tlv.Blob) (*AuxLeaves, error) {
	var l AuxLeaves
	err := l.Decode(bytes.NewReader(blob))
	if err != nil {
		return nil, err
	}

	return &l, nil
}

// Encode serializes the AuxLeaves to the given io.Writer.
func (o *AuxLeaves) Encode(w io.Writer) error {
	records := []tlv.Record{
		o.OutgoingHtlcLeaves.Record(),
		o.IncomingHtlcLeaves.Record(),
	}

	o.LocalAuxLeaf.WhenSome(
		func(r tlv.RecordT[tlv.TlvType0, tapLeafRecord]) {
			records = append(records, r.Record())
		},
	)
	o.RemoteAuxLeaf.WhenSome(
		func(r tlv.RecordT[tlv.TlvType1, tapLeafRecord]) {
			records = append(records, r.Record())
		},
	)

	tlv.SortRecords(records)

	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(records...)
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the AuxLeaves from the given io.Reader.
func (o *AuxLeaves) Decode(r io.Reader) error {
	localAuxLeaf := o.LocalAuxLeaf.Zero()
	remoteAuxLeaf := o.RemoteAuxLeaf.Zero()

	tlvStream, err := tlv.NewStream(
		localAuxLeaf.Record(),
		remoteAuxLeaf.Record(),
		o.OutgoingHtlcLeaves.Record(),
		o.IncomingHtlcLeaves.Record(),
	)
	if err != nil {
		return err
	}

	tlvs, err := tlvStream.DecodeWithParsedTypes(r)
	if err != nil {
		return err
	}

	if _, ok := tlvs[localAuxLeaf.TlvType()]; ok {
		o.LocalAuxLeaf = tlv.SomeRecordT(localAuxLeaf)
	}

	if _, ok := tlvs[remoteAuxLeaf.TlvType()]; ok {
		o.RemoteAuxLeaf = tlv.SomeRecordT(remoteAuxLeaf)
	}

	return nil
}

// Record creates a Record out of a AuxLeaves using the
// eHtlcAuxLeafMapRecord and dHtlcAuxLeafMapRecord functions.
//
// NOTE: This is part of the tlv.RecordProducer interface.
func (o *AuxLeaves) Record() tlv.Record {
	size := func() uint64 {
		var (
			buf     bytes.Buffer
			scratch [8]byte
		)
		if err := eAuxLeaves(&buf, o, &scratch); err != nil {
			panic(err)
		}

		return uint64(buf.Len())
	}

	// Note that we set the type here as zero, as when used with a
	// tlv.RecordT, the type param will be used as the type.
	return tlv.MakeDynamicRecord(0, o, size, eAuxLeaves, dAuxLeaves)
}

// eAuxLeaves is an encoder for AuxLeaves.
func eAuxLeaves(w io.Writer, val interface{}, buf *[8]byte) error {
	if v, ok := val.(*AuxLeaves); ok {
		var leavesBuf bytes.Buffer
		if err := v.Encode(&leavesBuf); err != nil {
			return err
		}

		leavesBytes := leavesBuf.Bytes()
		return asset.InlineVarBytesEncoder(w, &leavesBytes, buf)
	}
	return tlv.NewTypeForEncodingErr(val, "*AuxLeaves")
}

// dAuxLeaves is a decoder for AuxLeaves.
func dAuxLeaves(r io.Reader, val interface{}, buf *[8]byte, _ uint64) error {
	if typ, ok := val.(*AuxLeaves); ok {
		var leavesBytes []byte
		err := asset.InlineVarBytesDecoder(
			r, &leavesBytes, buf, tlv.MaxRecordSize,
		)
		if err != nil {
			return err
		}

		var auxLeaves AuxLeaves
		err = auxLeaves.Decode(bytes.NewReader(leavesBytes))
		if err != nil {
			return err
		}

		*typ = auxLeaves
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "*AuxLeaves")
}

// Commitment is a record that represents the current state of a commitment.
// This entails all the (asset_id, amount, proof) tuples and other information
// that we may need to be able to sign the TAP portion of the commitment
// transaction.
type Commitment struct {
	// LocalAssets is a list of all asset outputs that represent the current
	// local asset balance of the commitment.
	LocalAssets tlv.RecordT[tlv.TlvType0, assetOutputListRecord]

	// RemoteAssets is a list of all asset outputs that represents the
	// current remote asset balance of the commitment.
	RemoteAssets tlv.RecordT[tlv.TlvType1, assetOutputListRecord]

	// OutgoingHtlcAssets is a list of all outgoing in-flight HTLCs and the
	// asset balance change that they represent.
	OutgoingHtlcAssets tlv.RecordT[tlv.TlvType2, htlcAssetOutput]

	// IncomingHtlcAssets is a list of all incoming in-flight HTLCs and the
	// asset balance change that they represent.
	IncomingHtlcAssets tlv.RecordT[tlv.TlvType3, htlcAssetOutput]

	// AuxLeaves are the auxiliary leaves that correspond to the commitment.
	AuxLeaves tlv.RecordT[tlv.TlvType4, AuxLeaves]
}

// NewCommitment creates a new Commitment record with the given local and remote
// assets, and incoming and outgoing HTLCs.
func NewCommitment(localAssets, remoteAssets []*AssetOutput, outgoingHtlcs,
	incomingHtlcs map[input.HtlcIndex][]*AssetOutput,
	auxLeaves lnwallet.CommitAuxLeaves) *Commitment {

	return &Commitment{
		LocalAssets: tlv.NewRecordT[tlv.TlvType0](
			assetOutputListRecord{
				outputs: localAssets,
			},
		),
		RemoteAssets: tlv.NewRecordT[tlv.TlvType1](
			assetOutputListRecord{
				outputs: remoteAssets,
			},
		),
		OutgoingHtlcAssets: tlv.NewRecordT[tlv.TlvType2](
			newHtlcAssetOutput(outgoingHtlcs),
		),
		IncomingHtlcAssets: tlv.NewRecordT[tlv.TlvType3](
			newHtlcAssetOutput(incomingHtlcs),
		),
		AuxLeaves: tlv.NewRecordT[tlv.TlvType4](
			NewAuxLeaves(
				auxLeaves.LocalAuxLeaf, auxLeaves.RemoteAuxLeaf,
				auxLeaves.OutgoingHtlcLeaves,
				auxLeaves.IncomingHtlcLeaves,
			),
		),
	}
}

// records returns the records that make up the Commitment.
func (c *Commitment) records() []tlv.Record {
	return []tlv.Record{
		c.LocalAssets.Record(),
		c.RemoteAssets.Record(),
		c.OutgoingHtlcAssets.Record(),
		c.IncomingHtlcAssets.Record(),
		c.AuxLeaves.Record(),
	}
}

// Encode serializes the Commitment to the given io.Writer.
func (c *Commitment) Encode(w io.Writer) error {
	tlvRecords := c.records()

	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(tlvRecords...)
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the Commitment from the given io.Reader.
func (c *Commitment) Decode(r io.Reader) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(c.records()...)
	if err != nil {
		return err
	}

	return tlvStream.Decode(r)
}

// Bytes returns the serialized Commitment record.
func (c *Commitment) Bytes() []byte {
	var buf bytes.Buffer
	_ = c.Encode(&buf)
	return buf.Bytes()
}

// Leaves returns the auxiliary leaves that correspond to the commitment.
func (c *Commitment) Leaves() lnwallet.CommitAuxLeaves {
	leaves := lnwallet.CommitAuxLeaves{
		OutgoingHtlcLeaves: make(input.AuxTapLeaves),
		IncomingHtlcLeaves: make(input.AuxTapLeaves),
	}
	c.AuxLeaves.Val.LocalAuxLeaf.WhenSome(
		func(r tlv.RecordT[tlv.TlvType0, tapLeafRecord]) {
			leaves.LocalAuxLeaf = lfn.Some(r.Val.leaf)
		},
	)
	c.AuxLeaves.Val.RemoteAuxLeaf.WhenSome(
		func(r tlv.RecordT[tlv.TlvType1, tapLeafRecord]) {
			leaves.RemoteAuxLeaf = lfn.Some(r.Val.leaf)
		},
	)

	outgoing := c.AuxLeaves.Val.OutgoingHtlcLeaves.Val.htlcAuxLeaves
	for htlcIndex := range outgoing {
		outgoingLeaf := outgoing[htlcIndex]

		var leaf input.HtlcAuxLeaf
		outgoingLeaf.AuxLeaf.WhenSome(
			func(r tlv.RecordT[tlv.TlvType0, tapLeafRecord]) {
				leaf.AuxTapLeaf = lfn.Some(r.Val.leaf)
			},
		)
		outgoingLeaf.SecondLevelLeaf.WhenSome(
			func(r tlv.RecordT[tlv.TlvType1, tapLeafRecord]) {
				leaf.SecondLevelLeaf = lfn.Some(r.Val.leaf)
			},
		)

		leaves.OutgoingHtlcLeaves[htlcIndex] = leaf
	}

	incoming := c.AuxLeaves.Val.IncomingHtlcLeaves.Val.htlcAuxLeaves
	for htlcIndex := range incoming {
		incomingLeaf := incoming[htlcIndex]

		var leaf input.HtlcAuxLeaf
		incomingLeaf.AuxLeaf.WhenSome(
			func(r tlv.RecordT[tlv.TlvType0, tapLeafRecord]) {
				leaf.AuxTapLeaf = lfn.Some(r.Val.leaf)
			},
		)
		incomingLeaf.SecondLevelLeaf.WhenSome(
			func(r tlv.RecordT[tlv.TlvType1, tapLeafRecord]) {
				leaf.SecondLevelLeaf = lfn.Some(r.Val.leaf)
			},
		)

		leaves.IncomingHtlcLeaves[htlcIndex] = leaf
	}

	return leaves
}

// DecodeCommitment deserializes a Commitment from the given blob.
func DecodeCommitment(blob tlv.Blob) (*Commitment, error) {
	var c Commitment
	err := c.Decode(bytes.NewReader(blob))
	if err != nil {
		return nil, err
	}

	return &c, nil
}

// Htlc is a record that represents the capacity change related to an in-flight
// HTLC. This entails all the (asset_id, amount) tuples and other information
// that we may need to be able to update the TAP portion of a commitment
// balance.
type Htlc struct {
	// Amounts is a list of asset balances that are changed by the HTLC.
	Amounts tlv.RecordT[tlv.TlvType0, assetBalanceListRecord]
}

// NewHtlc creates a new Htlc record with the given funded assets.
func NewHtlc(amounts []*AssetBalance) *Htlc {
	return &Htlc{
		Amounts: tlv.NewRecordT[tlv.TlvType0](
			assetBalanceListRecord{
				balances: amounts,
			},
		),
	}
}

// Balances returns the list of asset balances that are updated in the Htlc
// struct.
func (o *Htlc) Balances() []*AssetBalance {
	return o.Amounts.Val.balances
}

// records returns the records that make up the Htlc.
func (o *Htlc) records() []tlv.Record {
	return []tlv.Record{
		o.Amounts.Record(),
	}
}

// Encode serializes the Htlc to the given io.Writer.
func (o *Htlc) Encode(w io.Writer) error {
	tlvRecords := o.records()

	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(tlvRecords...)
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the Htlc from the given io.Reader.
func (o *Htlc) Decode(r io.Reader) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(o.records()...)
	if err != nil {
		return err
	}

	return tlvStream.Decode(r)
}

// DecodeHtlc deserializes a Htlc from the given blob.
func DecodeHtlc(blob tlv.Blob) (*Htlc, error) {
	var h Htlc
	err := h.Decode(bytes.NewReader(blob))
	if err != nil {
		return nil, err
	}

	return &h, nil
}

// CommitSig is a record that represents the commitment signatures for a certain
// commit height.
type CommitSig struct {
	// PartialSig is the partial signatures and nonces for the asset funding
	// output.
	// TODO(guggero): Do we actually need this, if we're doing OP_TRUE in
	// the funding script at the asset level?
	PartialSig tlv.RecordT[tlv.TlvType0, assetSigListRecord]

	// HtlcPartialSigs is a map of HTLC indices to partial signatures and
	// nonces for the HTLCs.
	HtlcPartialSigs tlv.RecordT[tlv.TlvType1, htlcPartialSigsRecord]
}

// NewCommitSig creates a new CommitSig record with the given partial sigs.
func NewCommitSig(fundingSigs []*AssetSig,
	htlcSigs map[input.HtlcIndex][]*AssetSig) *CommitSig {

	var htlcPartialSigs map[input.HtlcIndex]assetSigListRecord
	if len(htlcSigs) > 0 {
		htlcPartialSigs = make(map[input.HtlcIndex]assetSigListRecord)
		for htlcIndex := range htlcSigs {
			htlcPartialSigs[htlcIndex] = assetSigListRecord{
				sigs: htlcSigs[htlcIndex],
			}
		}
	}

	return &CommitSig{
		PartialSig: tlv.NewRecordT[tlv.TlvType0](
			assetSigListRecord{
				sigs: fundingSigs,
			},
		),
		HtlcPartialSigs: tlv.NewRecordT[tlv.TlvType1](
			htlcPartialSigsRecord{
				htlcPartialSigs: htlcPartialSigs,
			},
		),
	}
}

// records returns the records that make up the CommitSig.
func (c *CommitSig) records() []tlv.Record {
	return []tlv.Record{
		c.PartialSig.Record(),
		c.HtlcPartialSigs.Record(),
	}
}

// Encode serializes the CommitSig to the given io.Writer.
func (c *CommitSig) Encode(w io.Writer) error {
	tlvRecords := c.records()

	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(tlvRecords...)
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the CommitSig from the given io.Reader.
func (c *CommitSig) Decode(r io.Reader) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(c.records()...)
	if err != nil {
		return err
	}

	return tlvStream.Decode(r)
}

// DecodeCommitSig deserializes a CommitSig from the given blob.
func DecodeCommitSig(blob tlv.Blob) (*CommitSig, error) {
	var c CommitSig
	err := c.Decode(bytes.NewReader(blob))
	if err != nil {
		return nil, err
	}

	return &c, nil
}

// HtlcAuxLeaf is a record that represents the auxiliary leaf of an HTLC and
// the optional second level leaf. The second level leaf is optional because it
// is not set in every case of the HTLC creation flow.
type HtlcAuxLeaf struct {
	// AuxLeaf is the auxiliary leaf that corresponds to the HTLC.
	AuxLeaf tlv.OptionalRecordT[tlv.TlvType0, tapLeafRecord]

	// SecondLevelLeaf is the auxiliary leaf that corresponds to the second
	// level HTLC. If this is not set, it means that the commitment
	// transaction isn't complete yet and the second level leaf couldn't yet
	// be created
	SecondLevelLeaf tlv.OptionalRecordT[tlv.TlvType1, tapLeafRecord]
}

// NewHtlcAuxLeaf creates a new HtlcAuxLeaf record with the given funded assets.
func NewHtlcAuxLeaf(leaf input.HtlcAuxLeaf) HtlcAuxLeaf {
	var auxLeaf HtlcAuxLeaf

	leaf.AuxTapLeaf.WhenSome(func(leaf txscript.TapLeaf) {
		auxLeaf.AuxLeaf = tlv.SomeRecordT[tlv.TlvType0](
			tlv.NewRecordT[tlv.TlvType0](tapLeafRecord{
				leaf: leaf,
			}),
		)
	})

	leaf.SecondLevelLeaf.WhenSome(func(leaf txscript.TapLeaf) {
		auxLeaf.SecondLevelLeaf = tlv.SomeRecordT[tlv.TlvType1](
			tlv.NewRecordT[tlv.TlvType1](tapLeafRecord{
				leaf: leaf,
			}),
		)
	})

	return auxLeaf
}

// Encode serializes the HtlcAuxLeaf to the given io.Writer.
func (o *HtlcAuxLeaf) Encode(w io.Writer) error {
	var records []tlv.Record
	o.AuxLeaf.WhenSome(func(r tlv.RecordT[tlv.TlvType0, tapLeafRecord]) {
		records = append(records, r.Record())
	})
	o.SecondLevelLeaf.WhenSome(
		func(r tlv.RecordT[tlv.TlvType1, tapLeafRecord]) {
			records = append(records, r.Record())
		},
	)

	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(records...)
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the HtlcAuxLeaf from the given io.Reader.
func (o *HtlcAuxLeaf) Decode(r io.Reader) error {
	auxLeaf := o.AuxLeaf.Zero()
	secondLevelLeaf := o.SecondLevelLeaf.Zero()

	tlvStream, err := tlv.NewStream(
		auxLeaf.Record(),
		secondLevelLeaf.Record(),
	)
	if err != nil {
		return err
	}

	tlvs, err := tlvStream.DecodeWithParsedTypes(r)
	if err != nil {
		return err
	}

	if _, ok := tlvs[auxLeaf.TlvType()]; ok {
		o.AuxLeaf = tlv.SomeRecordT(auxLeaf)
	}

	if _, ok := tlvs[secondLevelLeaf.TlvType()]; ok {
		o.SecondLevelLeaf = tlv.SomeRecordT(secondLevelLeaf)
	}

	return nil
}

// DecodeHtlcAuxLeaf deserializes a HtlcAuxLeaf from the given blob.
func DecodeHtlcAuxLeaf(blob tlv.Blob) (*HtlcAuxLeaf, error) {
	var h HtlcAuxLeaf
	err := h.Decode(bytes.NewReader(blob))
	if err != nil {
		return nil, err
	}

	return &h, nil
}

// AssetSig is a record that represents the signature for spending an asset
// output.
type AssetSig struct {
	// AssetID is the asset ID that the signature is for.
	AssetID tlv.RecordT[tlv.TlvType0, asset.ID]

	// Sig is the signature for the asset spend.
	Sig tlv.RecordT[tlv.TlvType1, lnwire.Sig]

	// SigHashType is the sigHash type that was used to create the
	// signature.
	SigHashType tlv.RecordT[tlv.TlvType2, uint32]
}

// NewAssetSig creates a new AssetSig record with the given
// asset ID and partial sig.
func NewAssetSig(assetID asset.ID, sig lnwire.Sig,
	sigHashType txscript.SigHashType) *AssetSig {

	return &AssetSig{
		AssetID: tlv.NewRecordT[tlv.TlvType0](assetID),
		Sig:     tlv.NewRecordT[tlv.TlvType1](sig),
		SigHashType: tlv.NewPrimitiveRecord[tlv.TlvType2](
			uint32(sigHashType),
		),
	}
}

// records returns the records that make up the AssetSig.
func (a *AssetSig) records() []tlv.Record {
	return []tlv.Record{
		a.AssetID.Record(),
		a.Sig.Record(),
		a.SigHashType.Record(),
	}
}

// encode serializes the AssetOutput to the given io.Writer.
func (a *AssetSig) encode(w io.Writer) error {
	tlvRecords := a.records()

	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(tlvRecords...)
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// decode deserializes the AssetSig from the given io.Reader.
func (a *AssetSig) decode(r io.Reader) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(a.records()...)
	if err != nil {
		return err
	}

	err = tlvStream.Decode(r)
	if err != nil {
		return err
	}

	// We need to force the signature type to be a Schnorr signature for the
	// unit tests to pass.
	a.Sig.Val.ForceSchnorr()

	return nil
}

// assetSigListRecord is a record that represents a list of asset signatures.
type assetSigListRecord struct {
	sigs []*AssetSig
}

// Record creates a Record out of a assetSigListRecord using the passed
// eAssetSigListRecord and dAssetSigListRecord functions.
//
// NOTE: This is part of the tlv.RecordProducer interface.
func (l *assetSigListRecord) Record() tlv.Record {
	size := func() uint64 {
		var (
			buf     bytes.Buffer
			scratch [8]byte
		)
		err := eAssetSigListRecord(&buf, &l.sigs, &scratch)
		if err != nil {
			panic(err)
		}

		return uint64(buf.Len())
	}

	// Note that we set the type here as zero, as when used with a
	// tlv.RecordT, the type param will be used as the type.
	return tlv.MakeDynamicRecord(
		0, &l.sigs, size, eAssetSigListRecord, dAssetSigListRecord,
	)
}

// Encode serializes the assetSigListRecord to the given io.Writer.
func (l *assetSigListRecord) Encode(w io.Writer) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(l.Record())
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the assetSigListRecord from the given io.Reader.
func (l *assetSigListRecord) Decode(r io.Reader) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(l.Record())
	if err != nil {
		return err
	}

	return tlvStream.Decode(r)
}

// encodeAssetSigListRecord serializes a assetSigListRecord to a byte slice.
func encodeAssetSigListRecord(rec assetSigListRecord) ([]byte, error) {
	var buf bytes.Buffer
	err := rec.Encode(&buf)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// decodeAssetSigListRecord deserializes a assetSigListRecord from the
// given blob.
func decodeAssetSigListRecord(rec []byte) (*assetSigListRecord, error) {
	var h assetSigListRecord
	err := h.Decode(bytes.NewReader(rec))
	if err != nil {
		return nil, err
	}

	return &h, nil
}

// eAssetSigListRecord is an encoder for assetSigListRecord.
func eAssetSigListRecord(w io.Writer, val interface{}, buf *[8]byte) error {
	if v, ok := val.(*[]*AssetSig); ok {
		numOutputs := uint64(len(*v))
		if err := tlv.WriteVarInt(w, numOutputs, buf); err != nil {
			return err
		}
		var sigsBuf bytes.Buffer
		for _, sig := range *v {
			if err := sig.encode(&sigsBuf); err != nil {
				return err
			}
			sigBytes := sigsBuf.Bytes()
			err := asset.InlineVarBytesEncoder(w, &sigBytes, buf)
			if err != nil {
				return err
			}
			sigsBuf.Reset()
		}
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "*[]*AssetSig")
}

// dAssetSigListRecord is a decoder for assetSigListRecord.
func dAssetSigListRecord(r io.Reader, val interface{}, buf *[8]byte,
	_ uint64) error {

	if typ, ok := val.(*[]*AssetSig); ok {
		numSigs, err := tlv.ReadVarInt(r, buf)
		if err != nil {
			return err
		}

		// Avoid OOM by limiting the number of sigs we accept.
		if numSigs > MaxNumOutputs {
			return fmt.Errorf("%w: too many signatures",
				ErrListInvalid)
		}

		if numSigs == 0 {
			return nil
		}

		sigs := make([]*AssetSig, numSigs)
		for i := uint64(0); i < numSigs; i++ {
			var outputBytes []byte
			err := asset.InlineVarBytesDecoder(
				r, &outputBytes, buf, OutputMaxSize,
			)
			if err != nil {
				return err
			}
			sigs[i] = &AssetSig{}
			err = sigs[i].decode(bytes.NewReader(outputBytes))
			if err != nil {
				return err
			}
		}
		*typ = sigs
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "*[]*AssetSig")
}

// htlcPartialSigsRecord is a record that represents a map of HTLC indices to
// partial signatures (with nonce).
type htlcPartialSigsRecord struct {
	htlcPartialSigs map[input.HtlcIndex]assetSigListRecord
}

// Record creates a Record out of a htlcPartialSigsRecord using the
// eHtlcPartialSigsRecord and dHtlcPartialSigsRecord functions.
//
// NOTE: This is part of the tlv.RecordProducer interface.
func (h *htlcPartialSigsRecord) Record() tlv.Record {
	size := func() uint64 {
		var (
			buf     bytes.Buffer
			scratch [8]byte
		)
		err := eHtlcPartialSigsRecord(
			&buf, &h.htlcPartialSigs, &scratch,
		)
		if err != nil {
			panic(err)
		}

		return uint64(buf.Len())
	}

	// Note that we set the type here as zero, as when used with a
	// tlv.RecordT, the type param will be used as the type.
	return tlv.MakeDynamicRecord(
		0, &h.htlcPartialSigs, size, eHtlcPartialSigsRecord,
		dHtlcPartialSigsRecord,
	)
}

// Encode serializes the htlcPartialSigsRecord to the given io.Writer.
func (h *htlcPartialSigsRecord) Encode(w io.Writer) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(h.Record())
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the htlcPartialSigsRecord from the given io.Reader.
func (h *htlcPartialSigsRecord) Decode(r io.Reader) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(h.Record())
	if err != nil {
		return err
	}

	return tlvStream.Decode(r)
}

// eHtlcPartialSigsRecord is an encoder for htlcPartialSigsRecord.
func eHtlcPartialSigsRecord(w io.Writer, val interface{}, buf *[8]byte) error {
	if v, ok := val.(*map[input.HtlcIndex]assetSigListRecord); ok {
		numHtlcs := uint64(len(*v))
		if err := tlv.WriteVarInt(w, numHtlcs, buf); err != nil {
			return err
		}
		var htlcBuf bytes.Buffer
		for htlcIndex, auxSig := range *v {
			err := tlv.WriteVarInt(w, htlcIndex, buf)
			if err != nil {
				return err
			}
			if err := auxSig.Encode(&htlcBuf); err != nil {
				return err
			}
			htlcBytes := htlcBuf.Bytes()
			err = asset.InlineVarBytesEncoder(
				w, &htlcBytes, buf,
			)
			if err != nil {
				return err
			}
			htlcBuf.Reset()
		}
		return nil
	}
	return tlv.NewTypeForEncodingErr(
		val, "*map[input.HtlcIndex]assetSigListRecord",
	)
}

// dHtlcPartialSigsRecord is a decoder for htlcPartialSigsRecord.
func dHtlcPartialSigsRecord(r io.Reader, val interface{}, buf *[8]byte,
	_ uint64) error {

	if typ, ok := val.(*map[input.HtlcIndex]assetSigListRecord); ok {
		numHtlcs, err := tlv.ReadVarInt(r, buf)
		if err != nil {
			return err
		}

		// Avoid OOM by limiting the number of HTLCs we accept.
		if numHtlcs > MaxNumHTLCs {
			return fmt.Errorf("%w: too many HTLCs", ErrListInvalid)
		}

		if numHtlcs == 0 {
			return nil
		}

		htlcs := make(map[input.HtlcIndex]assetSigListRecord, numHtlcs)
		for i := uint64(0); i < numHtlcs; i++ {
			htlcIndex, err := tlv.ReadVarInt(r, buf)
			if err != nil {
				return err
			}

			var htlcBytes []byte
			err = asset.InlineVarBytesDecoder(
				r, &htlcBytes, buf, tlv.MaxRecordSize,
			)
			if err != nil {
				return err
			}
			var rec assetSigListRecord
			err = rec.Decode(bytes.NewReader(htlcBytes))
			if err != nil {
				return err
			}

			htlcs[htlcIndex] = rec
		}
		*typ = htlcs
		return nil
	}
	return tlv.NewTypeForEncodingErr(
		val, "*map[input.HtlcIndex]assetSigListRecord",
	)
}

// htlcAuxLeafMapRecord is a record that represents a map of HTLC indices to
// HtlcAuxLeaf records.
type htlcAuxLeafMapRecord struct {
	htlcAuxLeaves map[input.HtlcIndex]HtlcAuxLeaf
}

// newHtlcAuxLeafMapRecord creates a new htlcAuxLeafMapRecord record with the
// given HTLC aux leaves.
func newHtlcAuxLeafMapRecord(
	leaves map[input.HtlcIndex]input.HtlcAuxLeaf) htlcAuxLeafMapRecord {

	if leaves == nil {
		return htlcAuxLeafMapRecord{}
	}

	htlcLeaves := make(map[input.HtlcIndex]HtlcAuxLeaf)
	for htlcIndex := range leaves {
		htlcLeaves[htlcIndex] = NewHtlcAuxLeaf(leaves[htlcIndex])
	}

	return htlcAuxLeafMapRecord{
		htlcAuxLeaves: htlcLeaves,
	}
}

// Record creates a Record out of a htlcAuxLeafMapRecord using the
// eHtlcAuxLeafMapRecord and dHtlcAuxLeafMapRecord functions.
//
// NOTE: This is part of the tlv.RecordProducer interface.
func (l *htlcAuxLeafMapRecord) Record() tlv.Record {
	size := func() uint64 {
		var (
			buf     bytes.Buffer
			scratch [8]byte
		)
		err := eHtlcAuxLeafMapRecord(&buf, &l.htlcAuxLeaves, &scratch)
		if err != nil {
			panic(err)
		}

		return uint64(buf.Len())
	}

	// Note that we set the type here as zero, as when used with a
	// tlv.RecordT, the type param will be used as the type.
	return tlv.MakeDynamicRecord(
		0, &l.htlcAuxLeaves, size, eHtlcAuxLeafMapRecord,
		dHtlcAuxLeafMapRecord,
	)
}

// Encode serializes the htlcPartialSigsRecord to the given io.Writer.
func (l *htlcAuxLeafMapRecord) Encode(w io.Writer) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(l.Record())
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the htlcPartialSigsRecord from the given io.Reader.
func (l *htlcAuxLeafMapRecord) Decode(r io.Reader) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(l.Record())
	if err != nil {
		return err
	}

	return tlvStream.Decode(r)
}

// eHtlcAuxLeafMapRecord is an encoder for htlcAuxLeafMapRecord.
func eHtlcAuxLeafMapRecord(w io.Writer, val interface{}, buf *[8]byte) error {
	if v, ok := val.(*map[input.HtlcIndex]HtlcAuxLeaf); ok {
		numHtlcs := uint64(len(*v))
		if err := tlv.WriteVarInt(w, numHtlcs, buf); err != nil {
			return err
		}
		var htlcBuf bytes.Buffer
		for htlcIndex, auxLeaf := range *v {
			err := tlv.WriteVarInt(w, htlcIndex, buf)
			if err != nil {
				return err
			}
			if err := auxLeaf.Encode(&htlcBuf); err != nil {
				return err
			}
			leafBytes := htlcBuf.Bytes()
			err = asset.InlineVarBytesEncoder(
				w, &leafBytes, buf,
			)
			if err != nil {
				return err
			}
			htlcBuf.Reset()
		}
		return nil
	}
	return tlv.NewTypeForEncodingErr(
		val, "*map[input.HtlcIndex]HtlcAuxLeaf",
	)
}

// dHtlcAuxLeafMapRecord is a decoder for htlcAuxLeafMapRecord.
func dHtlcAuxLeafMapRecord(r io.Reader, val interface{}, buf *[8]byte,
	_ uint64) error {

	if typ, ok := val.(*map[input.HtlcIndex]HtlcAuxLeaf); ok {
		numHtlcs, err := tlv.ReadVarInt(r, buf)
		if err != nil {
			return err
		}

		// Avoid OOM by limiting the number of HTLCs we accept.
		if numHtlcs > MaxNumHTLCs {
			return fmt.Errorf("%w: too many HTLCs", ErrListInvalid)
		}

		if numHtlcs == 0 {
			return nil
		}

		htlcs := make(map[input.HtlcIndex]HtlcAuxLeaf, numHtlcs)
		for i := uint64(0); i < numHtlcs; i++ {
			htlcIndex, err := tlv.ReadVarInt(r, buf)
			if err != nil {
				return err
			}

			var leavesBytes []byte
			err = asset.InlineVarBytesDecoder(
				r, &leavesBytes, buf, tlv.MaxRecordSize,
			)
			if err != nil {
				return err
			}
			var rec HtlcAuxLeaf
			err = rec.Decode(bytes.NewReader(leavesBytes))
			if err != nil {
				return err
			}

			htlcs[htlcIndex] = rec
		}
		*typ = htlcs
		return nil
	}
	return tlv.NewTypeForEncodingErr(
		val, "*map[input.HtlcIndex]HtlcAuxLeaf",
	)
}

// AssetBalance is a record that represents the amount of an asset that is
// being transferred or is available to be spent.
type AssetBalance struct {
	// AssetID is the ID of the asset that this output is associated with.
	AssetID tlv.RecordT[tlv.TlvType0, asset.ID]

	// Amount is the amount of the asset that this output represents.
	Amount tlv.RecordT[tlv.TlvType1, uint64]
}

// NewAssetBalance creates a new AssetBalance record with the given asset ID and
// amount.
func NewAssetBalance(assetID asset.ID, amount uint64) *AssetBalance {
	return &AssetBalance{
		AssetID: tlv.NewRecordT[tlv.TlvType0](assetID),
		Amount:  tlv.NewPrimitiveRecord[tlv.TlvType1](amount),
	}
}

// records returns the records that make up the AssetBalance.
func (o *AssetBalance) records() []tlv.Record {
	return []tlv.Record{
		o.AssetID.Record(),
		o.Amount.Record(),
	}
}

// encode serializes the AssetBalance to the given io.Writer.
func (o *AssetBalance) encode(w io.Writer) error {
	tlvRecords := o.records()

	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(tlvRecords...)
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// decode deserializes the AssetBalance from the given io.Reader.
func (o *AssetBalance) decode(r io.Reader) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(o.records()...)
	if err != nil {
		return err
	}

	return tlvStream.Decode(r)
}

// Sum returns the sum of the amounts of all the asset balances in the list.
func Sum(balances []*AssetBalance) uint64 {
	var sum uint64
	for _, balance := range balances {
		sum += balance.Amount.Val
	}
	return sum
}

// AssetOutput is a record that represents a single asset UTXO.
type AssetOutput struct {
	// AssetBalance is the asset ID and amount of the output.
	AssetBalance

	// Proof is the last transition proof that proves this output was
	// committed to in the Bitcoin transaction that anchors this asset
	// output.
	Proof tlv.RecordT[tlv.TlvType2, proof.Proof]
}

// NewAssetOutput creates a new AssetOutput record with the given asset ID,
// amount, and proof.
func NewAssetOutput(assetID asset.ID, amount uint64,
	p proof.Proof) *AssetOutput {

	return &AssetOutput{
		AssetBalance: AssetBalance{
			AssetID: tlv.NewRecordT[tlv.TlvType0](assetID),
			Amount:  tlv.NewPrimitiveRecord[tlv.TlvType1](amount),
		},
		Proof: tlv.NewRecordT[tlv.TlvType2](p),
	}
}

// records returns the records that make up the AssetOutput.
func (o *AssetOutput) records() []tlv.Record {
	return []tlv.Record{
		o.AssetID.Record(),
		o.Amount.Record(),
		o.Proof.Record(),
	}
}

// encode serializes the AssetOutput to the given io.Writer.
func (o *AssetOutput) encode(w io.Writer) error {
	tlvRecords := o.records()

	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(tlvRecords...)
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// decode deserializes the AssetOutput from the given io.Reader.
func (o *AssetOutput) decode(r io.Reader) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(o.records()...)
	if err != nil {
		return err
	}

	return tlvStream.Decode(r)
}

// OutputSum returns the sum of the amounts of all the asset outputs in the
// list.
func OutputSum(outputs []*AssetOutput) uint64 {
	var sum uint64
	for _, output := range outputs {
		sum += output.Amount.Val
	}
	return sum
}

// htlcAssetOutput is a record that represents a list of asset outputs that are
// associated with a particular HTLC index.
type htlcAssetOutput struct {
	htlcOutputs map[input.HtlcIndex]assetOutputListRecord
}

// newHtlcAssetOutput creates a new htlcAssetOutput record with the given HTLC
// outputs.
func newHtlcAssetOutput(
	htlcOutputs map[input.HtlcIndex][]*AssetOutput) htlcAssetOutput {

	if htlcOutputs == nil {
		return htlcAssetOutput{}
	}

	htlcOutputsRecord := make(map[input.HtlcIndex]assetOutputListRecord)
	for htlcIndex := range htlcOutputs {
		htlcOutputsRecord[htlcIndex] = assetOutputListRecord{
			outputs: htlcOutputs[htlcIndex],
		}
	}

	return htlcAssetOutput{
		htlcOutputs: htlcOutputsRecord,
	}
}

// Record creates a Record out of a htlcAssetOutput using the
// eHtlcAssetOutput and dHtlcAssetOutput functions.
//
// NOTE: This is part of the tlv.RecordProducer interface.
func (l *htlcAssetOutput) Record() tlv.Record {
	size := func() uint64 {
		var (
			buf     bytes.Buffer
			scratch [8]byte
		)
		err := eHtlcAssetOutput(&buf, &l.htlcOutputs, &scratch)
		if err != nil {
			panic(err)
		}

		return uint64(buf.Len())
	}

	// Note that we set the type here as zero, as when used with a
	// tlv.RecordT, the type param will be used as the type.
	return tlv.MakeDynamicRecord(
		0, &l.htlcOutputs, size, eHtlcAssetOutput, dHtlcAssetOutput,
	)
}

// Encode serializes the htlcAssetOutput to the given io.Writer.
func (l *htlcAssetOutput) Encode(w io.Writer) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(l.Record())
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the htlcAssetOutput from the given io.Reader.
func (l *htlcAssetOutput) Decode(r io.Reader) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(l.Record())
	if err != nil {
		return err
	}

	return tlvStream.Decode(r)
}

// eHtlcAssetOutput is an encoder for htlcAssetOutput.
func eHtlcAssetOutput(w io.Writer, val interface{}, buf *[8]byte) error {
	if v, ok := val.(*map[input.HtlcIndex]assetOutputListRecord); ok {
		numHtlcs := uint64(len(*v))
		if err := tlv.WriteVarInt(w, numHtlcs, buf); err != nil {
			return err
		}
		var htlcBuf bytes.Buffer
		for htlcIndex, balance := range *v {
			err := tlv.WriteVarInt(w, htlcIndex, buf)
			if err != nil {
				return err
			}
			if err := balance.Encode(&htlcBuf); err != nil {
				return err
			}
			balanceBytes := htlcBuf.Bytes()
			err = asset.InlineVarBytesEncoder(
				w, &balanceBytes, buf,
			)
			if err != nil {
				return err
			}
			htlcBuf.Reset()
		}
		return nil
	}
	return tlv.NewTypeForEncodingErr(
		val, "map[input.HtlcIndex]assetOutputListRecord",
	)
}

// dHtlcAssetOutput is a decoder for htlcAssetOutput.
func dHtlcAssetOutput(r io.Reader, val interface{}, buf *[8]byte,
	_ uint64) error {

	if typ, ok := val.(*map[input.HtlcIndex]assetOutputListRecord); ok {
		numHtlcs, err := tlv.ReadVarInt(r, buf)
		if err != nil {
			return err
		}

		// Avoid OOM by limiting the number of HTLCs we accept.
		if numHtlcs > MaxNumHTLCs {
			return fmt.Errorf("%w: too many HTLCs", ErrListInvalid)
		}

		if numHtlcs == 0 {
			return nil
		}

		htlcs := make(
			map[input.HtlcIndex]assetOutputListRecord, numHtlcs,
		)
		for i := uint64(0); i < numHtlcs; i++ {
			htlcIndex, err := tlv.ReadVarInt(r, buf)
			if err != nil {
				return err
			}

			var balanceBytes []byte
			err = asset.InlineVarBytesDecoder(
				r, &balanceBytes, buf, OutputMaxSize,
			)
			if err != nil {
				return err
			}
			var rec assetOutputListRecord
			err = rec.Decode(bytes.NewReader(balanceBytes))
			if err != nil {
				return err
			}

			htlcs[htlcIndex] = rec
		}
		*typ = htlcs
		return nil
	}
	return tlv.NewTypeForEncodingErr(
		val, "map[input.HtlcIndex]assetOutputListRecord",
	)
}

// assetBalanceListRecord is a record that represents a list of asset balances.
type assetBalanceListRecord struct {
	balances []*AssetBalance
}

// Sum returns the sum of the amounts of all the asset balances in the list.
func (l *assetBalanceListRecord) Sum() uint64 {
	return Sum(l.balances)
}

// Record creates a Record out of a assetBalanceListRecord using the
// eAssetBalanceList and dAssetBalanceList functions.
//
// NOTE: This is part of the tlv.RecordProducer interface.
func (l *assetBalanceListRecord) Record() tlv.Record {
	size := func() uint64 {
		var (
			buf     bytes.Buffer
			scratch [8]byte
		)
		err := eAssetBalanceList(&buf, &l.balances, &scratch)
		if err != nil {
			panic(err)
		}

		return uint64(buf.Len())
	}

	// Note that we set the type here as zero, as when used with a
	// tlv.RecordT, the type param will be used as the type.
	return tlv.MakeDynamicRecord(
		0, &l.balances, size, eAssetBalanceList, dAssetBalanceList,
	)
}

// Encode serializes the assetBalanceListRecord to the given io.Writer.
func (l *assetBalanceListRecord) Encode(w io.Writer) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(l.Record())
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the assetBalanceListRecord from the given io.Reader.
func (l *assetBalanceListRecord) Decode(r io.Reader) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(l.Record())
	if err != nil {
		return err
	}

	return tlvStream.Decode(r)
}

// eAssetBalanceList is an encoder for assetBalanceListRecord.
func eAssetBalanceList(w io.Writer, val interface{}, buf *[8]byte) error {
	if v, ok := val.(*[]*AssetBalance); ok {
		numBalances := uint64(len(*v))
		if err := tlv.WriteVarInt(w, numBalances, buf); err != nil {
			return err
		}
		var outputBuf bytes.Buffer
		for _, balance := range *v {
			if err := balance.encode(&outputBuf); err != nil {
				return err
			}
			balanceBytes := outputBuf.Bytes()
			err := asset.InlineVarBytesEncoder(
				w, &balanceBytes, buf,
			)
			if err != nil {
				return err
			}
			outputBuf.Reset()
		}
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "[]*AssetBalance")
}

// dAssetBalanceList is a decoder for assetBalanceListRecord.
func dAssetBalanceList(r io.Reader, val interface{}, buf *[8]byte,
	_ uint64) error {

	if typ, ok := val.(*[]*AssetBalance); ok {
		numBalances, err := tlv.ReadVarInt(r, buf)
		if err != nil {
			return err
		}

		// Avoid OOM by limiting the number of balances we accept.
		if numBalances > MaxNumOutputs {
			return fmt.Errorf("%w: too many balances",
				ErrListInvalid)
		}

		if numBalances == 0 {
			return nil
		}

		outputs := make([]*AssetBalance, numBalances)
		for i := uint64(0); i < numBalances; i++ {
			var outputBytes []byte
			err := asset.InlineVarBytesDecoder(
				r, &outputBytes, buf, OutputMaxSize,
			)
			if err != nil {
				return err
			}
			outputs[i] = &AssetBalance{}
			err = outputs[i].decode(bytes.NewReader(outputBytes))
			if err != nil {
				return err
			}
		}
		*typ = outputs
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "[]*AssetBalance")
}

// assetOutputListRecord is a record that represents a list of asset outputs.
type assetOutputListRecord struct {
	outputs []*AssetOutput
}

// Sum returns the sum of the amounts of all the asset outputs in the list.
func (l *assetOutputListRecord) Sum() uint64 {
	var sum uint64
	for _, output := range l.outputs {
		sum += output.Amount.Val
	}
	return sum
}

// Record creates a Record out of a assetOutputListRecord using the passed
// eAssetOutputList and dAssetOutputList functions.
//
// NOTE: This is part of the tlv.RecordProducer interface.
func (l *assetOutputListRecord) Record() tlv.Record {
	size := func() uint64 {
		var (
			buf     bytes.Buffer
			scratch [8]byte
		)
		err := eAssetOutputList(&buf, &l.outputs, &scratch)
		if err != nil {
			panic(err)
		}

		return uint64(buf.Len())
	}

	// Note that we set the type here as zero, as when used with a
	// tlv.RecordT, the type param will be used as the type.
	return tlv.MakeDynamicRecord(
		0, &l.outputs, size, eAssetOutputList, dAssetOutputList,
	)
}

// Encode serializes the assetOutputListRecord to the given io.Writer.
func (l *assetOutputListRecord) Encode(w io.Writer) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(l.Record())
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the assetOutputListRecord from the given io.Reader.
func (l *assetOutputListRecord) Decode(r io.Reader) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(l.Record())
	if err != nil {
		return err
	}

	return tlvStream.Decode(r)
}

// eAssetOutputList is an encoder for assetOutputListRecord.
func eAssetOutputList(w io.Writer, val interface{}, buf *[8]byte) error {
	if v, ok := val.(*[]*AssetOutput); ok {
		numOutputs := uint64(len(*v))
		if err := tlv.WriteVarInt(w, numOutputs, buf); err != nil {
			return err
		}
		var outputBuf bytes.Buffer
		for _, output := range *v {
			if err := output.encode(&outputBuf); err != nil {
				return err
			}
			outputBytes := outputBuf.Bytes()
			err := asset.InlineVarBytesEncoder(w, &outputBytes, buf)
			if err != nil {
				return err
			}
			outputBuf.Reset()
		}
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "*[]*AssetOutput")
}

// dAssetOutputList is a decoder for assetOutputListRecord.
func dAssetOutputList(r io.Reader, val interface{}, buf *[8]byte,
	_ uint64) error {

	if typ, ok := val.(*[]*AssetOutput); ok {
		numOutputs, err := tlv.ReadVarInt(r, buf)
		if err != nil {
			return err
		}

		// Avoid OOM by limiting the number of outputs we accept.
		if numOutputs > MaxNumOutputs {
			return fmt.Errorf("%w: too many outputs",
				ErrListInvalid)
		}

		if numOutputs == 0 {
			return nil
		}

		outputs := make([]*AssetOutput, numOutputs)
		for i := uint64(0); i < numOutputs; i++ {
			var outputBytes []byte
			err := asset.InlineVarBytesDecoder(
				r, &outputBytes, buf, OutputMaxSize,
			)
			if err != nil {
				return err
			}
			outputs[i] = &AssetOutput{}
			err = outputs[i].decode(bytes.NewReader(outputBytes))
			if err != nil {
				return err
			}
		}
		*typ = outputs
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "*[]*AssetOutput")
}

// tapLeafRecord is a record that represents a TapLeaf.
type tapLeafRecord struct {
	leaf txscript.TapLeaf
}

// Record creates a Record out of a tapLeafRecord using the passed
// eTapLeafRecord and dTapLeafRecord functions.
//
// NOTE: This is part of the tlv.RecordProducer interface.
func (l *tapLeafRecord) Record() tlv.Record {
	size := func() uint64 {
		var (
			buf     bytes.Buffer
			scratch [8]byte
		)
		err := eTapLeafRecord(&buf, l, &scratch)
		if err != nil {
			panic(err)
		}

		return uint64(buf.Len())
	}

	// Note that we set the type here as zero, as when used with a
	// tlv.RecordT, the type param will be used as the type.
	return tlv.MakeDynamicRecord(0, l, size, eTapLeafRecord, dTapLeafRecord)
}

// Encode serializes the tapLeafRecord to the given io.Writer.
func (l *tapLeafRecord) Encode(w io.Writer) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(l.Record())
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the tapLeafRecord from the given io.Reader.
func (l *tapLeafRecord) Decode(r io.Reader) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(l.Record())
	if err != nil {
		return err
	}

	return tlvStream.Decode(r)
}

// eTapLeafRecord is an encoder for tapLeafRecord.
func eTapLeafRecord(w io.Writer, val interface{}, buf *[8]byte) error {
	if v, ok := val.(*tapLeafRecord); ok {
		err := tlv.EUint8T(w, uint8(v.leaf.LeafVersion), buf)
		if err != nil {
			return err
		}

		scriptLen := uint64(len(v.leaf.Script))
		if err := tlv.WriteVarInt(w, scriptLen, buf); err != nil {
			return err
		}
		return asset.InlineVarBytesEncoder(w, &v.leaf.Script, buf)
	}
	return tlv.NewTypeForEncodingErr(val, "*tapLeafRecord")
}

// dTapLeafRecord is a decoder for tapLeafRecord.
func dTapLeafRecord(r io.Reader, val interface{}, buf *[8]byte,
	l uint64) error {

	if typ, ok := val.(*tapLeafRecord); ok {
		var leafVersion uint8
		if err := tlv.DUint8(r, &leafVersion, buf, 1); err != nil {
			return err
		}

		leaf := txscript.TapLeaf{
			LeafVersion: txscript.TapscriptLeafVersion(leafVersion),
		}

		scriptLen, err := tlv.ReadVarInt(r, buf)
		if err != nil {
			return err
		}

		// Avoid OOM by limiting the size of script we accept.
		if scriptLen > tlv.MaxRecordSize {
			return fmt.Errorf("%w: script too long", ErrListInvalid)
		}

		err = asset.InlineVarBytesDecoder(
			r, &leaf.Script, buf, tlv.MaxRecordSize,
		)
		if err != nil {
			return err
		}

		*typ = tapLeafRecord{
			leaf: leaf,
		}
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "*tapLeafRecord")
}
