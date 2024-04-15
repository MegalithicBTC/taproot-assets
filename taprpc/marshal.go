package taprpc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightningnetwork/lnd/keychain"
)

// KeyLookup is used to determine whether a key is under the control of the
// local wallet.
type KeyLookup interface {
	// IsLocalKey returns true if the key is under the control of the
	// wallet and can be derived by it.
	IsLocalKey(ctx context.Context, desc keychain.KeyDescriptor) bool
}

// marshalKeyDescriptor marshals the native key descriptor into the RPC
// counterpart.
func MarshalKeyDescriptor(desc keychain.KeyDescriptor) *KeyDescriptor {
	var rawKeyBytes []byte
	if desc.PubKey != nil {
		rawKeyBytes = desc.PubKey.SerializeCompressed()
	}

	return &KeyDescriptor{
		RawKeyBytes: rawKeyBytes,
		KeyLoc: &KeyLocator{
			KeyFamily: uint32(desc.KeyLocator.Family),
			KeyIndex:  desc.KeyLocator.Index,
		},
	}
}

// UnmarshalKeyDescriptor parses the RPC key descriptor into the native
// counterpart.
func UnmarshalKeyDescriptor(rpcDesc *KeyDescriptor) (keychain.KeyDescriptor,
	error) {

	var (
		desc keychain.KeyDescriptor
		err  error
	)

	// The public key of a key descriptor is mandatory. It is enough to
	// locate the corresponding private key in the backing wallet. But to
	// speed things up (and for additional context), the locator should
	// still be provided if available.
	desc.PubKey, err = btcec.ParsePubKey(rpcDesc.RawKeyBytes)
	if err != nil {
		return desc, err
	}

	if rpcDesc.KeyLoc != nil {
		desc.KeyLocator = keychain.KeyLocator{
			Family: keychain.KeyFamily(rpcDesc.KeyLoc.KeyFamily),
			Index:  rpcDesc.KeyLoc.KeyIndex,
		}
	}

	return desc, nil
}

// FetchAssetMeta allows a caller to fetch the reveal meta data for an asset
// either by the asset ID for that asset, or a meta hash.
// UnmarshalScriptKey parses the RPC script key into the native counterpart.
func UnmarshalScriptKey(rpcKey *ScriptKey) (*asset.ScriptKey, error) {
	var (
		scriptKey asset.ScriptKey
		err       error
	)

	// The script public key is a Taproot key, so 32-byte x-only.
	scriptKey.PubKey, err = schnorr.ParsePubKey(rpcKey.PubKey)
	if err != nil {
		return nil, err
	}

	// The key descriptor is optional for script keys that are completely
	// independent of the backing wallet.
	if rpcKey.KeyDesc != nil {
		keyDesc, err := UnmarshalKeyDescriptor(rpcKey.KeyDesc)
		if err != nil {
			return nil, err
		}
		scriptKey.TweakedScriptKey = &asset.TweakedScriptKey{
			RawKey: keyDesc,

			// The tweak is optional, if it's empty it means the key
			// is derived using BIP-0086.
			Tweak: rpcKey.TapTweak,
		}
	}

	return &scriptKey, nil
}

// MarshalScriptKey marshals the native script key into the RPC counterpart.
func MarshalScriptKey(scriptKey asset.ScriptKey) *ScriptKey {
	rpcScriptKey := &ScriptKey{
		PubKey: schnorr.SerializePubKey(scriptKey.PubKey),
	}

	if scriptKey.TweakedScriptKey != nil {
		rpcScriptKey.KeyDesc = MarshalKeyDescriptor(
			scriptKey.TweakedScriptKey.RawKey,
		)
		rpcScriptKey.TapTweak = scriptKey.TweakedScriptKey.Tweak
	}

	return rpcScriptKey
}

// UnmarshalAssetVersion parses an asset version from the RPC variant.
func UnmarshalAssetVersion(version AssetVersion) (asset.Version, error) {
	// For now we'll only support two asset versions. The ones in the
	// future should be reserved for future use, so we disallow unknown
	// versions.
	switch version {
	case AssetVersion_ASSET_VERSION_V0:
		return asset.V0, nil

	case AssetVersion_ASSET_VERSION_V1:
		return asset.V1, nil

	default:
		return 0, fmt.Errorf("unknown asset version: %v", version)
	}
}

// MarshalAssetVersion parses an asset version from the RPC variant.
func MarshalAssetVersion(version asset.Version) (AssetVersion, error) {
	// For now we'll only support two asset versions. The ones in the
	// future should be reserved for future use, so we disallow unknown
	// versions.
	switch version {
	case asset.V0:
		return AssetVersion_ASSET_VERSION_V0, nil

	case asset.V1:
		return AssetVersion_ASSET_VERSION_V1, nil

	default:
		return 0, fmt.Errorf("unknown asset version: %v", version)
	}
}

// MarshalGenesisInfo marshals the native asset genesis into the RPC
// counterpart.
func MarshalGenesisInfo(gen *asset.Genesis, assetType asset.Type) *GenesisInfo {
	return &GenesisInfo{
		GenesisPoint: gen.FirstPrevOut.String(),
		AssetType:    AssetType(assetType),
		Name:         gen.Tag,
		MetaHash:     gen.MetaHash[:],
		AssetId:      fn.ByteSlice(gen.ID()),
		OutputIndex:  gen.OutputIndex,
	}
}

func UnmarshalGenesisInfo(rpcGen *GenesisInfo) (*asset.Genesis, error) {
	firstPrevOut, err := wire.NewOutPointFromString(rpcGen.GenesisPoint)
	if err != nil {
		return nil, err
	}

	if len(rpcGen.MetaHash) != sha256.Size {
		return nil, fmt.Errorf("meta hash must be %d bytes",
			sha256.Size)
	}

	return &asset.Genesis{
		FirstPrevOut: *firstPrevOut,
		Tag:          rpcGen.Name,
		MetaHash:     fn.ToArray[[32]byte](rpcGen.MetaHash),
		OutputIndex:  rpcGen.OutputIndex,
		Type:         asset.Type(rpcGen.AssetType),
	}, nil
}

func UnmarshalGroupKeyRequest(req *GroupKeyRequest) (*asset.GroupKeyRequest,
	error) {

	rawKey, err := UnmarshalKeyDescriptor(req.RawKey)
	if err != nil {
		return nil, err
	}

	anchorGen, err := UnmarshalGenesisInfo(req.AnchorGenesis)
	if err != nil {
		return nil, err
	}

	if len(req.TapscriptRoot) != 0 &&
		len(req.TapscriptRoot) != sha256.Size {

		return nil, fmt.Errorf("tapscript root must be %d bytes",
			sha256.Size)
	}

	var newAsset asset.Asset
	err = newAsset.Decode(bytes.NewReader(req.NewAsset))
	if err != nil {
		return nil, err
	}

	return &asset.GroupKeyRequest{
		RawKey:        rawKey,
		AnchorGen:     *anchorGen,
		TapscriptRoot: req.TapscriptRoot,
		NewAsset:      &newAsset,
	}, nil
}

// MarshalGroupKeyRequest marshals the native group key request into the RPC
// counterpart.
func MarshalGroupKeyRequest(ctx context.Context,
	req *asset.GroupKeyRequest) (*GroupKeyRequest, error) {

	err := req.Validate()
	if err != nil {
		return nil, err
	}

	var assetBuf bytes.Buffer
	err = req.NewAsset.Encode(&assetBuf)
	if err != nil {
		return nil, err
	}

	return &GroupKeyRequest{
		RawKey: MarshalKeyDescriptor(req.RawKey),
		AnchorGenesis: MarshalGenesisInfo(
			&req.AnchorGen, req.NewAsset.Type,
		),
		TapscriptRoot: req.TapscriptRoot,
		NewAsset:      assetBuf.Bytes(),
	}, nil
}

// MarshalGroupVirtualTx marshals the native asset group virtual transaction
// into the RPC counterpart.
func MarshalGroupVirtualTx(genTx *asset.GroupVirtualTx) (*GroupVirtualTx,
	error) {

	var groupTxBuf bytes.Buffer
	err := genTx.Tx.Serialize(&groupTxBuf)
	if err != nil {
		return nil, err
	}

	rpcPrevOut := TxOut{
		Value:    genTx.PrevOut.Value,
		PkScript: genTx.PrevOut.PkScript,
	}

	return &GroupVirtualTx{
		Transaction: groupTxBuf.Bytes(),
		PrevOut:     &rpcPrevOut,
		GenesisId:   fn.ByteSlice(genTx.GenID),
		TweakedKey:  genTx.TweakedKey.SerializeCompressed(),
	}, nil
}

func UnmarshalGroupVirtualTx(genTx *GroupVirtualTx) (*asset.GroupVirtualTx,
	error) {

	var virtualTx wire.MsgTx
	err := virtualTx.Deserialize(bytes.NewReader(genTx.Transaction))
	if err != nil {
		return nil, err
	}

	if genTx.PrevOut == nil {
		return nil, fmt.Errorf("prevout cannot be empty")
	}

	prevOut := wire.TxOut{
		Value:    genTx.PrevOut.Value,
		PkScript: genTx.PrevOut.PkScript,
	}
	if len(genTx.GenesisId) != sha256.Size {
		return nil, fmt.Errorf("genesis id must be %d bytes",
			sha256.Size)
	}

	tweakedKey, err := btcec.ParsePubKey(genTx.TweakedKey)
	if err != nil {
		return nil, err
	}

	return &asset.GroupVirtualTx{
		Tx:         virtualTx,
		PrevOut:    prevOut,
		GenID:      asset.ID(genTx.GenesisId),
		TweakedKey: *tweakedKey,
	}, nil
}

func UnmarshalGroupWitness(wit *GroupWitness) (*asset.PendingGroupWitness,
	error) {

	// Assert that a given witness stack does not exceed the limit used by
	// the VM.
	checkWitnessSize := func(wit [][]byte) error {
		witSize := fn.Reduce(wit,
			func(totalSize int, witItem []byte) int {
				totalSize += len(witItem)
				return totalSize
			})
		if witSize > blockchain.MaxBlockWeight {
			return fmt.Errorf("asset group witness too large: %d",
				witSize)
		}

		return nil
	}

	if len(wit.GenesisId) != sha256.Size {
		return nil, fmt.Errorf("invalid genesis id length: "+
			"%d, %x", len(wit.GenesisId), wit.GenesisId)
	}

	sizeErr := checkWitnessSize(wit.Witness)
	if sizeErr != nil {
		return nil, sizeErr
	}

	return &asset.PendingGroupWitness{
		GenID:   asset.ID(wit.GenesisId),
		Witness: wit.Witness,
	}, nil
}

// MarshalAsset converts an asset to its rpc representation.
func MarshalAsset(ctx context.Context, a *asset.Asset,
	isSpent, withWitness bool,
	keyRing KeyLookup) (*Asset, error) {

	scriptKeyIsLocal := false
	if a.ScriptKey.TweakedScriptKey != nil && keyRing != nil {
		scriptKeyIsLocal = keyRing.IsLocalKey(
			ctx, a.ScriptKey.RawKey,
		)
	}

	assetVersion, err := MarshalAssetVersion(a.Version)
	if err != nil {
		return nil, err
	}

	rpcAsset := &Asset{
		Version:          assetVersion,
		AssetGenesis:     MarshalGenesisInfo(&a.Genesis, a.Type),
		Amount:           a.Amount,
		LockTime:         a.LockTime,
		RelativeLockTime: a.RelativeLockTime,
		ScriptVersion:    int32(a.ScriptVersion),
		ScriptKey:        a.ScriptKey.PubKey.SerializeCompressed(),
		ScriptKeyIsLocal: scriptKeyIsLocal,
		IsSpent:          isSpent,
		IsBurn:           a.IsBurn(),
	}

	if a.GroupKey != nil {
		var (
			rawKey        []byte
			groupWitness  []byte
			tapscriptRoot []byte
			err           error
		)

		if a.GroupKey.RawKey.PubKey != nil {
			rawKey = a.GroupKey.RawKey.PubKey.SerializeCompressed()
		}
		if len(a.GroupKey.Witness) != 0 {
			groupWitness, err = asset.SerializeGroupWitness(
				a.GroupKey.Witness,
			)
			if err != nil {
				return nil, err
			}
		}
		if len(a.GroupKey.TapscriptRoot) != 0 {
			tapscriptRoot = a.GroupKey.TapscriptRoot[:]
		}
		rpcAsset.AssetGroup = &AssetGroup{
			RawGroupKey: rawKey,
			TweakedGroupKey: a.GroupKey.GroupPubKey.
				SerializeCompressed(),
			AssetWitness:  groupWitness,
			TapscriptRoot: tapscriptRoot,
		}
	}

	if withWitness {
		for idx := range a.PrevWitnesses {
			witness := a.PrevWitnesses[idx]

			prevID := witness.PrevID
			rpcPrevID := &PrevInputAsset{
				AnchorPoint: prevID.OutPoint.String(),
				AssetId:     prevID.ID[:],
				ScriptKey:   prevID.ScriptKey[:],
			}

			var rpcSplitCommitment *SplitCommitment
			if witness.SplitCommitment != nil {
				rootAsset, err := MarshalAsset(
					ctx, &witness.SplitCommitment.RootAsset,
					false, true, nil,
				)
				if err != nil {
					return nil, err
				}

				rpcSplitCommitment = &SplitCommitment{
					RootAsset: rootAsset,
				}
			}

			rpcAsset.PrevWitnesses = append(
				rpcAsset.PrevWitnesses, &PrevWitness{
					PrevId:          rpcPrevID,
					TxWitness:       witness.TxWitness,
					SplitCommitment: rpcSplitCommitment,
				},
			)
		}
	}

	return rpcAsset, nil
}
