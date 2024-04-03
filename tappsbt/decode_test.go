package tappsbt_test

import (
	"bytes"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/stretchr/testify/require"
)

var (
	testParams = &address.MainNetTap

	generatedTestVectorName = "psbt_encoding_generated.json"

	allTestVectorFiles = []string{
		generatedTestVectorName,
		"psbt_encoding_error_cases.json",
	}
)

// assertEqualPackets asserts that two packets are equal and prints a nice diff
// if they are not.
func assertEqualPackets(t *testing.T, expected, actual *tappsbt.VPacket) {
	if !reflect.DeepEqual(expected.ChainParams, actual.ChainParams) {
		require.Equal(t, expected.ChainParams, actual.ChainParams)
		require.Fail(t, "ChainParams not equal")
	}

	require.Len(t, expected.Inputs, len(actual.Inputs))
	for idx := range expected.Inputs {
		e := expected.Inputs[idx]
		a := actual.Inputs[idx]

		if !reflect.DeepEqual(e, a) {
			require.Equal(t, e, a, "input %d not equal", idx)
			require.Fail(t, "input not equal")
		}
	}

	require.Len(t, expected.Outputs, len(actual.Outputs))

	for idx := range expected.Outputs {
		e := expected.Outputs[idx]
		a := actual.Outputs[idx]

		if !reflect.DeepEqual(e, a) {
			require.Equalf(t, e, a, "output %d not equal", idx)
			require.Fail(t, "output not equal")
		}
	}
}

// TestEncodingDecoding tests the decoding of a virtual packet from raw bytes.
func TestEncodingDecoding(t *testing.T) {
	t.Parallel()

	testVectors := &tappsbt.TestVectors{}
	assertEncodingDecoding := func(comment string, pkg *tappsbt.VPacket) {
		// Encode the packet as a PSBT packet then as base64.
		packet, err := pkg.EncodeAsPsbt()
		require.NoError(t, err)

		var buf bytes.Buffer
		err = packet.Serialize(&buf)
		require.NoError(t, err)

		testVectors.ValidTestCases = append(
			testVectors.ValidTestCases, &tappsbt.ValidTestCase{
				Packet: tappsbt.NewTestFromVPacket(t, pkg),
				Expected: base64.StdEncoding.EncodeToString(
					buf.Bytes(),
				),
				Comment: comment,
			},
		)

		// Make sure we can read the packet back from the raw bytes.
		decoded, err := tappsbt.NewFromRawBytes(&buf, false)
		require.NoError(t, err)

		assertEqualPackets(t, pkg, decoded)

		// Also make sure we can decode the packet from the base PSBT.
		decoded, err = tappsbt.NewFromPsbt(packet)
		require.NoError(t, err)

		assertEqualPackets(t, pkg, decoded)
	}

	testCases := []struct {
		name string
		pkg  func(t *testing.T) *tappsbt.VPacket
	}{{
		name: "minimal packet",
		pkg: func(t *testing.T) *tappsbt.VPacket {
			proofCourierAddr := address.RandProofCourierAddr(t)
			addr, _, _ := address.RandAddr(
				t, testParams, proofCourierAddr,
			)

			pkg, err := tappsbt.FromAddresses(
				[]*address.Tap{addr.Tap}, 1,
			)
			require.NoError(t, err)
			pkg.Outputs = append(pkg.Outputs, &tappsbt.VOutput{
				ScriptKey: asset.RandScriptKey(t),
			})

			return pkg
		},
	}, {
		name: "random packet",
		pkg: func(t *testing.T) *tappsbt.VPacket {
			return tappsbt.RandPacket(t)
		},
	}}

	for _, testCase := range testCases {
		testCase := testCase

		success := t.Run(testCase.name, func(t *testing.T) {
			pkg := testCase.pkg(t)
			assertEncodingDecoding(testCase.name, pkg)
		})
		if !success {
			return
		}
	}

	// Write test vectors to file. This is a no-op if the "gen_test_vectors"
	// build tag is not set.
	test.WriteTestVectors(t, generatedTestVectorName, testVectors)
}

// TestBIPTestVectors tests that the BIP test vectors are passing.
func TestBIPTestVectors(t *testing.T) {
	t.Parallel()

	for idx := range allTestVectorFiles {
		var (
			fileName    = allTestVectorFiles[idx]
			testVectors = &tappsbt.TestVectors{}
		)
		test.ParseTestVectors(t, fileName, &testVectors)
		t.Run(fileName, func(tt *testing.T) {
			tt.Parallel()

			runBIPTestVector(tt, testVectors)
		})
	}
}

// runBIPTestVector runs the tests in a single BIP test vector file.
func runBIPTestVector(t *testing.T, testVectors *tappsbt.TestVectors) {
	for _, validCase := range testVectors.ValidTestCases {
		validCase := validCase

		t.Run(validCase.Comment, func(tt *testing.T) {
			tt.Parallel()

			p := validCase.Packet.ToVPacket(t)

			packetString, err := p.B64Encode()
			require.NoError(tt, err)

			areEqual := validCase.Expected == packetString

			// Create nice diff if things don't match.
			if !areEqual {
				expectedPacket, err := tappsbt.NewFromRawBytes(
					strings.NewReader(validCase.Expected),
					true,
				)
				require.NoError(tt, err)

				require.Equal(tt, p, expectedPacket)

				// Make sure we still fail the test.
				require.Equal(
					tt, validCase.Expected, packetString,
				)
			}

			// We also want to make sure that the address is decoded
			// correctly from the encoded TLV stream.
			decoded, err := tappsbt.NewFromRawBytes(
				strings.NewReader(validCase.Expected), true,
			)
			require.NoError(tt, err)

			require.Equal(tt, p, decoded)

			// And finally, we want to make sure that if we get a
			// raw byte blob we can also decode the packet and the
			// result is the same.
			rawBytes, err := base64.StdEncoding.DecodeString(
				validCase.Expected,
			)
			require.NoError(tt, err)
			decodedFromBytes, err := tappsbt.NewFromRawBytes(
				bytes.NewReader(rawBytes), false,
			)
			require.NoError(tt, err)

			require.Equal(tt, p, decodedFromBytes)
		})
	}

	for _, invalidCase := range testVectors.ErrorTestCases {
		invalidCase := invalidCase

		t.Run(invalidCase.Comment, func(tt *testing.T) {
			tt.Parallel()

			require.PanicsWithValue(tt, invalidCase.Error, func() {
				invalidCase.Packet.ToVPacket(tt)
			})
		})
	}
}
