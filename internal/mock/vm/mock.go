package vm

import (
	assetmock "github.com/lightninglabs/taproot-assets/internal/mock/asset"
	commitmentmock "github.com/lightninglabs/taproot-assets/internal/mock/commitment"
)

type ValidTestCase struct {
	Asset    *assetmock.TestAsset        `json:"asset"`
	SplitSet commitmentmock.TestSplitSet `json:"split_set"`
	InputSet commitmentmock.TestInputSet `json:"input_set"`
	Comment  string                      `json:"comment"`
}

type ErrorTestCase struct {
	Asset    *assetmock.TestAsset        `json:"asset"`
	SplitSet commitmentmock.TestSplitSet `json:"split_set"`
	InputSet commitmentmock.TestInputSet `json:"input_set"`
	Error    string                      `json:"error"`
	Comment  string                      `json:"comment"`
}

type TestVectors struct {
	ValidTestCases []*ValidTestCase `json:"valid_test_cases"`
	ErrorTestCases []*ErrorTestCase `json:"error_test_cases"`
}
