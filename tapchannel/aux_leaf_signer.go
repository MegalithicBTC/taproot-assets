package tapchannel

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightninglabs/taproot-assets/vm"
	"github.com/lightningnetwork/lnd/channeldb"
	lfn "github.com/lightningnetwork/lnd/fn"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/btcwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/tlv"
)

// LeafSignerConfig defines the configuration for the auxiliary leaf signer.
type LeafSignerConfig struct {
	ChainParams *address.ChainParams

	AssetWallet *tapfreighter.AssetWallet
}

// AuxLeafSigner is a Taproot Asset auxiliary leaf signer that can be used to
// sign auxiliary leaves for Taproot Asset channels.
type AuxLeafSigner struct {
	startOnce sync.Once
	stopOnce  sync.Once

	cfg *LeafSignerConfig

	// ContextGuard provides a wait group and main quit channel that can be
	// used to create guarded contexts.
	*fn.ContextGuard
}

// NewAuxLeafSigner creates a new Taproot Asset auxiliary leaf signer based on
// the passed config.
func NewAuxLeafSigner(cfg *LeafSignerConfig) *AuxLeafSigner {
	return &AuxLeafSigner{
		cfg: cfg,
		ContextGuard: &fn.ContextGuard{
			DefaultTimeout: DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}
}

// Start attempts to start a new aux leaf signer.
func (s *AuxLeafSigner) Start() error {
	var startErr error
	s.startOnce.Do(func() {
		log.Info("Starting aux leaf signer")
	})
	return startErr
}

// Stop signals for a aux leaf signer to gracefully exit.
func (s *AuxLeafSigner) Stop() error {
	var stopErr error
	s.stopOnce.Do(func() {
		log.Info("Stopping aux leaf signer")

		close(s.Quit)
		s.Wg.Wait()
	})

	return stopErr
}

// A compile-time check to ensure that AuxLeafSigner fully implements the
// lnwallet.AuxSigner interface.
var _ lnwallet.AuxSigner = (*AuxLeafSigner)(nil)

// SubmitSecondLevelSigBatch takes a batch of aux sign jobs and processes them
// asynchronously.
func (s *AuxLeafSigner) SubmitSecondLevelSigBatch(
	chanState *channeldb.OpenChannel, commitTx *wire.MsgTx,
	jobs []lnwallet.AuxSigJob) error {

	s.Wg.Add(1)
	go s.processAuxSigBatch(chanState, commitTx, jobs)

	return nil
}

// PackSigs takes a series of aux signatures and packs them into a single blob
// that can be sent alongside the CommitSig messages.
func (s *AuxLeafSigner) PackSigs(
	sigBlob map[input.HtlcIndex]lfn.Option[tlv.Blob]) (lfn.Option[tlv.Blob],
	error) {

	htlcSigs := make(map[input.HtlcIndex][]*AssetSig, len(sigBlob))
	for htlcIndex := range sigBlob {
		err := lfn.MapOptionZ(
			sigBlob[htlcIndex], func(sigBlob tlv.Blob) error {
				assetSigs, err := decodeAssetSigListRecord(
					sigBlob,
				)
				if err != nil {
					return err
				}

				htlcSigs[htlcIndex] = assetSigs.sigs

				return nil
			},
		)
		if err != nil {
			return lfn.None[tlv.Blob](), fmt.Errorf("error "+
				"decoding asset sig list record: %w", err)
		}
	}

	commitSig := NewCommitSig(nil, htlcSigs)

	var buf bytes.Buffer
	if err := commitSig.Encode(&buf); err != nil {
		return lfn.None[tlv.Blob](), fmt.Errorf("error encoding "+
			"commit sig: %w", err)
	}

	return lfn.Some(buf.Bytes()), nil
}

// UnpackSigs takes a packed blob of signatures and returns the original
// signatures for each HTLC, keyed by HTLC index.
func (s *AuxLeafSigner) UnpackSigs(
	blob lfn.Option[tlv.Blob]) (map[input.HtlcIndex]lfn.Option[tlv.Blob],
	error) {

	if blob.IsNone() {
		return nil, nil
	}

	commitSig, err := DecodeCommitSig(blob.UnsafeFromSome())
	if err != nil {
		return nil, fmt.Errorf("error decoding commit sig: %w", err)
	}

	htlcSigRec := commitSig.HtlcPartialSigs.Val.htlcPartialSigs
	htlcSigs := make(map[input.HtlcIndex]lfn.Option[tlv.Blob])
	for htlcIndex := range htlcSigRec {
		htlcBlob, err := encodeAssetSigListRecord(htlcSigRec[htlcIndex])
		if err != nil {
			return nil, fmt.Errorf("error encoding asset sig list "+
				"record: %w", err)
		}

		htlcSigs[htlcIndex] = lfn.Some(htlcBlob)
	}

	return htlcSigs, nil
}

// VerifySecondLevelSigs attempts to synchronously verify a batch of aux sig
// jobs.
func (s *AuxLeafSigner) VerifySecondLevelSigs(chanState *channeldb.OpenChannel,
	commitTx *wire.MsgTx, verifyJobs []lnwallet.AuxVerifyJob) error {

	for idx := range verifyJobs {
		verifyJob := verifyJobs[idx]
		if verifyJob.SigBlob.IsNone() {
			return fmt.Errorf("signature blob is required")
		}

		assetSigs, err := decodeAssetSigListRecord(
			verifyJob.SigBlob.UnsafeFromSome(),
		)
		if err != nil {
			return fmt.Errorf("error decoding asset sig list "+
				"record: %w", err)
		}

		if verifyJob.CommitBlob.IsNone() {
			return fmt.Errorf("commit blob is required")
		}

		com, err := DecodeCommitment(
			verifyJob.CommitBlob.UnsafeFromSome(),
		)
		if err != nil {
			return fmt.Errorf("error decoding commitment: %w", err)
		}

		err = s.verifyHtlcSignature(
			chanState, commitTx, verifyJobs[idx].KeyRing,
			assetSigs.sigs, com, verifyJobs[idx].BaseAuxJob,
		)
		if err != nil {
			return fmt.Errorf("error verifying second level sig: "+
				"%w", err)
		}
	}

	return nil
}

// processAuxSigBatch processes a batch of aux sign jobs asynchronously.
//
// NOTE: This method must be called as a goroutine.
func (s *AuxLeafSigner) processAuxSigBatch(chanState *channeldb.OpenChannel,
	commitTx *wire.MsgTx, sigJobs []lnwallet.AuxSigJob) {

	defer s.Wg.Done()

	for idx := range sigJobs {
		sigJob := sigJobs[idx]
		cancelAndErr := func(err error) {
			close(sigJob.Cancel)
			sigJob.Resp <- lnwallet.AuxSigJobResp{
				Err: err,
			}
		}

		// If we're shutting down, we cancel the job and return.
		select {
		case <-s.Quit:
			cancelAndErr(fmt.Errorf("tapd is shutting down"))
			return

		default:
		}

		if sigJob.CommitBlob.IsNone() {
			cancelAndErr(fmt.Errorf("commit blob is required"))
			return
		}

		com, err := DecodeCommitment(sigJob.CommitBlob.UnsafeFromSome())
		if err != nil {
			cancelAndErr(fmt.Errorf("error decoding commitment: "+
				"%w", err))
			return
		}

		resp, err := s.generateHtlcSignature(
			chanState, commitTx, com, sigJob.SignDesc,
			sigJob.BaseAuxJob,
		)
		if err != nil {
			cancelAndErr(fmt.Errorf("error generating HTLC "+
				"signature: %w", err))
			return
		}

		// Success!
		sigJob.Resp <- resp
	}
}

// verifyHtlcSignature verifies the HTLC signature in the commitment transaction
// described by the sign job.
func (s *AuxLeafSigner) verifyHtlcSignature(chanState *channeldb.OpenChannel,
	commitTx *wire.MsgTx, keyRing lnwallet.CommitmentKeyRing,
	sigs []*AssetSig, com *Commitment,
	baseJob lnwallet.BaseAuxJob) error {

	vPackets, err := s.htlcSecondLevelPacketsFromCommit(
		chanState, commitTx, baseJob.KeyRing, com, baseJob,
	)
	if err != nil {
		return fmt.Errorf("error generating second level packets: %w",
			err)
	}

	for idx, vPacket := range vPackets {
		// This is a signature for a second-level HTLC, which always
		// only has one input and one output. But there might be
		// multiple asset IDs, which is why we might have multiple
		// signatures. But the order of the signatures and virtual
		// packets are expected to align.
		vIn := vPacket.Inputs[0]
		vOut := vPacket.Outputs[0]
		sig := sigs[idx]

		// Construct input set from the single input asset.
		prevAssets := commitment.InputSet{
			vIn.PrevID: vIn.Asset(),
		}
		newAsset := vOut.Asset

		// Now that we know we're not dealing with a genesis state
		// transition, we'll map our set of asset inputs and outputs to
		// the 1-input 1-output virtual transaction.
		virtualTx, _, err := tapscript.VirtualTx(newAsset, prevAssets)
		if err != nil {
			return err
		}

		validator := &schnorrSigValidator{
			pubKey: keyRing.RemoteHtlcKey,
		}

		return validator.validateSchnorrSig(
			virtualTx, vIn.Asset(), uint32(idx),
			txscript.SigHashType(sig.SigHashType.Val), sig.Sig.Val,
		)
	}

	return nil
}

// generateHtlcSignature generates the signature for the HTLC output in the
// commitment transaction described by the sign job.
func (s *AuxLeafSigner) generateHtlcSignature(chanState *channeldb.OpenChannel,
	commitTx *wire.MsgTx, commitment *Commitment,
	signDesc input.SignDescriptor,
	baseJob lnwallet.BaseAuxJob) (lnwallet.AuxSigJobResp, error) {

	vPackets, err := s.htlcSecondLevelPacketsFromCommit(
		chanState, commitTx, baseJob.KeyRing, commitment, baseJob,
	)
	if err != nil {
		return lnwallet.AuxSigJobResp{}, fmt.Errorf("error generating "+
			"second level packets: %w", err)
	}

	var sigs []*AssetSig
	for _, vPacket := range vPackets {
		vIn := vPacket.Inputs[0]

		leafToSign := txscript.TapLeaf{
			Script:      signDesc.WitnessScript,
			LeafVersion: txscript.BaseLeafVersion,
		}
		vIn.TaprootLeafScript = []*psbt.TaprootTapLeafScript{
			{
				Script:      leafToSign.Script,
				LeafVersion: leafToSign.LeafVersion,
			},
		}

		deriv, trDeriv := tappsbt.Bip32DerivationFromKeyDesc(
			signDesc.KeyDesc, s.cfg.ChainParams.HDCoinType,
		)
		vIn.Bip32Derivation = []*psbt.Bip32Derivation{deriv}
		vIn.TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{
			trDeriv,
		}
		vIn.TaprootBip32Derivation[0].LeafHashes = [][]byte{
			fn.ByteSlice(leafToSign.TapHash()),
		}
		vIn.SighashType = signDesc.HashType

		// Apply single or double tweaks if present in the sign
		// descriptor. At the same time, we apply the tweaks to a copy
		// of the public key, so we can validate the produced signature.
		signingKey := signDesc.KeyDesc.PubKey
		if len(signDesc.SingleTweak) > 0 {
			key := btcwallet.PsbtKeyTypeInputSignatureTweakSingle
			vIn.Unknowns = append(vIn.Unknowns, &psbt.Unknown{
				Key:   key,
				Value: signDesc.SingleTweak,
			})

			signingKey = input.TweakPubKeyWithTweak(
				signingKey, signDesc.SingleTweak,
			)
		}
		if signDesc.DoubleTweak != nil {
			key := btcwallet.PsbtKeyTypeInputSignatureTweakDouble
			vIn.Unknowns = append(vIn.Unknowns, &psbt.Unknown{
				Key:   key,
				Value: signDesc.DoubleTweak.Serialize(),
			})

			signingKey = input.DeriveRevocationPubkey(
				signingKey, signDesc.DoubleTweak.PubKey(),
			)
		}

		// We can now sign this virtual packet, as we've given the
		// wallet internal signer everything it needs to locate the key
		// and decide how to sign. Since the signature is only one of
		// two required, we can't use the default validator that would
		// check the full witness. Instead, we use a custom Schnorr
		// signature validator to validate the single signature we
		// produced.
		signed, err := s.cfg.AssetWallet.SignVirtualPacket(
			vPacket, tapfreighter.SkipInputProofVerify(),
			tapfreighter.WithValidator(&schnorrSigValidator{
				pubKey: signingKey,
			}),
		)
		if err != nil {
			return lnwallet.AuxSigJobResp{}, fmt.Errorf("error "+
				"signing virtual packet: %w", err)
		}

		if len(signed) != 1 || signed[0] != 0 {
			return lnwallet.AuxSigJobResp{}, fmt.Errorf("error " +
				"signing virtual packet, got no sig")
		}

		rawSig := vPacket.Outputs[0].Asset.Witnesses()[0].TxWitness[0]
		if signDesc.HashType != txscript.SigHashDefault {
			rawSig = rawSig[0:64]
		}

		sig, err := lnwire.NewSigFromSchnorrRawSignature(rawSig)
		if err != nil {
			return lnwallet.AuxSigJobResp{}, fmt.Errorf("error "+
				"converting raw sig to Schnorr: %w", err)
		}

		sigs = append(sigs, NewAssetSig(
			vIn.PrevID.ID, sig, signDesc.HashType,
		))
	}

	htlcBlob, err := encodeAssetSigListRecord(assetSigListRecord{
		sigs: sigs,
	})
	if err != nil {
		return lnwallet.AuxSigJobResp{}, fmt.Errorf("error encoding "+
			"asset sig list record: %w", err)
	}

	return lnwallet.AuxSigJobResp{
		SigBlob:   lfn.Some(htlcBlob),
		HtlcIndex: baseJob.HTLC.HtlcIndex,
	}, nil
}

// htlcSecondLevelPacketsFromCommit generates the HTLC second level packets from
// the commitment transaction.
func (s *AuxLeafSigner) htlcSecondLevelPacketsFromCommit(
	chanState *channeldb.OpenChannel, commitTx *wire.MsgTx,
	keyRing lnwallet.CommitmentKeyRing, commitment *Commitment,
	baseJob lnwallet.BaseAuxJob) ([]*tappsbt.VPacket, error) {

	var htlcOutputs []*AssetOutput

	// Find the HTLC in the commitment transaction, so we can extract the
	// HTLC asset outputs.
	for outIndex := range commitment.IncomingHtlcAssets.Val.htlcOutputs {
		if outIndex == baseJob.HTLC.HtlcIndex {
			incoming := commitment.IncomingHtlcAssets.Val
			htlcOutputs = incoming.htlcOutputs[outIndex].outputs

			break
		}
	}
	for outIndex := range commitment.OutgoingHtlcAssets.Val.htlcOutputs {
		if outIndex == baseJob.HTLC.HtlcIndex {
			outgoing := commitment.OutgoingHtlcAssets.Val
			htlcOutputs = outgoing.htlcOutputs[outIndex].outputs

			break
		}
	}

	// If we didn't find the HTLC outputs, we can't generate the HTLC
	// signature.
	if len(htlcOutputs) == 0 {
		return nil, fmt.Errorf("HTLC with index %d not found in "+
			"commitment TX", baseJob.HTLC.HtlcIndex)
	}

	packets, _, err := CreateSecondLevelHtlcPackets(
		chanState, commitTx, baseJob.HTLC.Amount.ToSatoshis(),
		keyRing, s.cfg.ChainParams, htlcOutputs,
	)
	if err != nil {
		return nil, fmt.Errorf("error creating second level HTLC "+
			"packets: %w", err)
	}

	return packets, nil
}

// schnorrSigValidator validates a single Schnorr signature against the given
// public key.
type schnorrSigValidator struct {
	pubKey *btcec.PublicKey
}

// ValidateWitnesses validates the generated witnesses of an asset transfer.
// This method explicitly expects a single signature to be present in the
// witness of each input, which must be valid for the state transition and the
// given public key. But the witness as a whole is not expected to be valid yet,
// as this might represent only a single signature of a multisig output. So the
// method name might be misleading, as the full witness is _not_ validated. But
// the interface we implement requires this method signature.
func (v *schnorrSigValidator) ValidateWitnesses(newAsset *asset.Asset,
	_ []*commitment.SplitAsset, prevAssets commitment.InputSet) error {

	// Now that we know we're not dealing with a genesis state
	// transition, we'll map our set of asset inputs and outputs to
	// the 1-input 1-output virtual transaction.
	virtualTx, _, err := tapscript.VirtualTx(newAsset, prevAssets)
	if err != nil {
		return err
	}

	for idx := range newAsset.PrevWitnesses {
		witness := newAsset.PrevWitnesses[idx]
		prevAsset, ok := prevAssets[*witness.PrevID]
		if !ok {
			return fmt.Errorf("%w: no prev asset for "+
				"input_prev_id=%v", vm.ErrNoInputs,
				spew.Sdump(witness.PrevID))
		}

		var (
			sigHashType = txscript.SigHashDefault
			sigBytes    []byte
		)
		switch {
		case len(witness.TxWitness[0]) == 64:
			sigBytes = witness.TxWitness[0]

		case len(witness.TxWitness[0]) == 65:
			sigBytes = witness.TxWitness[0][:64]
			sigHashType = txscript.SigHashType(
				witness.TxWitness[0][64],
			)

		default:
			return fmt.Errorf("invalid signature length: len=%d",
				len(witness.TxWitness[0]))
		}

		schnorrSig, err := lnwire.NewSigFromSchnorrRawSignature(
			sigBytes,
		)
		if err != nil {
			return err
		}

		return v.validateSchnorrSig(
			virtualTx, prevAsset, uint32(idx), sigHashType,
			schnorrSig,
		)
	}

	return nil
}

// validateSchnorrSig validates the given Schnorr signature against the public
// key of the validator and the sigHash of the asset transition.
func (v *schnorrSigValidator) validateSchnorrSig(virtualTx *wire.MsgTx,
	prevAsset *asset.Asset, idx uint32, sigHashType txscript.SigHashType,
	sig lnwire.Sig) error {

	prevOutFetcher, err := tapscript.InputPrevOutFetcher(*prevAsset)
	if err != nil {
		return err
	}

	// Update the virtual transaction input with details for the specific
	// Taproot Asset input and proceed to validate its witness.
	virtualTxCopy := asset.VirtualTxWithInput(
		virtualTx, prevAsset, idx, nil,
	)

	sigHashes := txscript.NewTxSigHashes(virtualTxCopy, prevOutFetcher)
	sigHash, err := txscript.CalcTaprootSignatureHash(
		sigHashes, sigHashType, virtualTxCopy, 0, prevOutFetcher,
	)

	signature, err := sig.ToSignature()
	if err != nil {
		return err
	}

	if !signature.Verify(sigHash, v.pubKey) {
		return fmt.Errorf("signature verification failed for sig %x "+
			"and public key %x", sig.RawBytes(),
			v.pubKey.SerializeCompressed())
	}

	return nil
}
