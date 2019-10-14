package roothash

import (
	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	roothash "github.com/oasislabs/oasis-core/go/roothash/api"
	"github.com/oasislabs/oasis-core/go/roothash/api/commitment"
	"github.com/oasislabs/oasis-core/go/tendermint/api"
)

const (
	// TransactionTag is a unique byte used to identify transactions
	// for the root hash application.
	TransactionTag byte = 0x02

	// AppName is the ABCI application name.
	AppName string = "999_roothash"
)

var (
	// TagUpdate is an ABCI transaction tag for marking transactions
	// which have been processed by roothash (value is TagUpdateValue).
	TagUpdate = []byte("roothash.update")
	// TagUpdateValue is the only allowed value for TagUpdate.
	TagUpdateValue = []byte("1")

	// TagMergeDiscrepancyDetected is an ABCI transaction tag for merge discrepancy
	// detected events (value is a CBOR serialized ValueMergeDiscrepancyDetected).
	TagMergeDiscrepancyDetected = []byte("roothash.merge-discrepancy")
	// TagComputeDiscrepancyDetected is an ABCI transaction tag for merge discrepancy
	// detected events (value is a CBOR serialized ValueComputeDiscrepancyDetected).
	TagComputeDiscrepancyDetected = []byte("roothash.compute-discrepancy")

	// TagFinalized is an ABCI transaction tag for finalized blocks
	// (value is a CBOR serialized ValueFinalized).
	TagFinalized = []byte("roothash.finalized")

	// QueryApp is a query for filtering transactions processed by
	// the root hash application.
	QueryApp = api.QueryForEvent([]byte(AppName), api.TagAppNameValue)

	// QueryUpdate is a query for filtering transactions where root hash
	// application state has been updated. This is required as state can
	//  change as part of foreign application transactions.
	QueryUpdate = api.QueryForEvent(TagUpdate, TagUpdateValue)
)

const (
	// QueryGetLatestBlock is a path for GetLatestBlock query.
	QueryGetLatestBlock = AppName + "/block"

	// QueryGetGenesisBlock is a path for GetGenesisBlock query.
	QueryGetGenesisBlock = AppName + "/genesis_block"

	// QueryGenesis is a path for Genesis query.
	QueryGenesis = AppName + "/genesis"
)

// Tx is a transaction to be accepted by the roothash app.
type Tx struct {
	*TxComputeCommit `json:"ComputeCommit,omitempty"`
	*TxMergeCommit   `json:"MergeCommit,omitempty"`
}

// TxComputeCommit is a transaction for submitting compute commitments.
type TxComputeCommit struct {
	ID      signature.PublicKey            `json:"id"`
	Commits []commitment.ComputeCommitment `json:"commits"`
}

// TxMergeCommit is a transaction for submitting merge commitments.
type TxMergeCommit struct {
	ID      signature.PublicKey          `json:"id"`
	Commits []commitment.MergeCommitment `json:"commits"`
}

// ValueFinalized is the value component of a TagFinalized.
type ValueFinalized struct {
	ID    signature.PublicKey `json:"id"`
	Round uint64              `json:"round"`
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (v *ValueFinalized) MarshalCBOR() []byte {
	return cbor.Marshal(v)
}

// UnmarshalCBOR deserializes a CBOR byte vector into the given type.
func (v *ValueFinalized) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, v)
}

// ValueMergeDiscrepancyDetected is the value component of a
// TagMergeDiscrepancyDetected.
type ValueMergeDiscrepancyDetected struct {
	Event roothash.MergeDiscrepancyDetectedEvent `json:"event"`
	ID    signature.PublicKey                    `json:"id"`
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (v *ValueMergeDiscrepancyDetected) MarshalCBOR() []byte {
	return cbor.Marshal(v)
}

// UnmarshalCBOR deserializes a CBOR byte vector into the given type.
func (v *ValueMergeDiscrepancyDetected) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, v)
}

// ValueComputeDiscrepancyDetected is the value component of a
// TagMergeDiscrepancyDetected.
type ValueComputeDiscrepancyDetected struct {
	ID    signature.PublicKey                      `json:"id"`
	Event roothash.ComputeDiscrepancyDetectedEvent `json:"event"`
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (v *ValueComputeDiscrepancyDetected) MarshalCBOR() []byte {
	return cbor.Marshal(v)
}

// UnmarshalCBOR deserializes a CBOR byte vector into the given type.
func (v *ValueComputeDiscrepancyDetected) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, v)
}
