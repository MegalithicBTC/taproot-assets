package tapchannel

import (
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightningnetwork/lnd/input"
)

// anyoneCanSpendScript is a simple script that allows anyone to spend the the
// output.
func anyoneCanSpendSript() []byte {
	return []byte{txscript.OP_TRUE}
}

// FundingScriptTree...
type FundingScriptTree struct {
	input.ScriptTree
}

// NewFundingScriptTree...
func NewFundingScriptTree() *FundingScriptTree {
	// First, we'll generate our OP_TRUE script.
	fundingScript := anyoneCanSpendSript()
	fundingTapLeaf := txscript.NewBaseTapLeaf(fundingScript)

	// With the funding script dervied, we'll now create the tapscript tree
	// from it.
	tapscriptTree := txscript.AssembleTaprootScriptTree(
		fundingTapLeaf,
	)

	tapScriptRoot := tapscriptTree.RootNode.TapHash()

	// Finally, we'll make the funding output script which actually uses a
	// NUMs key to force a script path only.
	fundingOutputKey := txscript.ComputeTaprootOutputKey(
		&input.TaprootNUMSKey, tapScriptRoot[:],
	)

	return &FundingScriptTree{
		ScriptTree: input.ScriptTree{
			InternalKey:   &input.TaprootNUMSKey,
			TaprootKey:    fundingOutputKey,
			TapscriptTree: tapscriptTree,
			TapscriptRoot: tapScriptRoot[:],
		},
	}
}
