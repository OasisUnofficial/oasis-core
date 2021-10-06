// Package commitment defines a roothash commitment.
package commitment

import (
	"errors"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/message"
)

var (
	// ExecutorSignatureContext is the signature context used to sign executor
	// worker commitments.
	ExecutorSignatureContext = signature.NewContext(
		"oasis-core/roothash: executor commitment",
		signature.WithChainSeparation(),
		signature.WithDynamicSuffix(" for runtime ", common.NamespaceHexSize),
	)

	// ComputeResultsHeaderSignatureContext is the signature context used to
	// sign compute results headers with RAK.
	ComputeResultsHeaderSignatureContext = signature.NewContext("oasis-core/roothash: compute results header")
)

// ComputeResultsHeader is the header of a computed batch output by a runtime. This
// header is a compressed representation (e.g., hashes instead of full content) of
// the actual results.
//
// These headers are signed by RAK inside the runtime and included in executor
// commitments.
//
// Keep the roothash RAK validation in sync with changes to this structure.
type ComputeResultsHeader struct {
	Round        uint64    `json:"round"`
	PreviousHash hash.Hash `json:"previous_hash"`

	// Optional fields (may be absent for failure indication).

	IORoot       *hash.Hash `json:"io_root,omitempty"`
	StateRoot    *hash.Hash `json:"state_root,omitempty"`
	MessagesHash *hash.Hash `json:"messages_hash,omitempty"`
}

// IsParentOf returns true iff the header is the parent of a child header.
func (h *ComputeResultsHeader) IsParentOf(child *block.Header) bool {
	if h.Round != child.Round+1 {
		return false
	}

	childHash := child.EncodedHash()
	return h.PreviousHash.Equal(&childHash)
}

// EncodedHash returns the encoded cryptographic hash of the header.
func (h *ComputeResultsHeader) EncodedHash() hash.Hash {
	return hash.NewFrom(h)
}

// ExecutorCommitmentFailure is the executor commitment failure reason.
type ExecutorCommitmentFailure uint8

const (
	// FailureNone indicates that no failure has occurred.
	FailureNone ExecutorCommitmentFailure = 0
	// FailureUnknown indicates a generic failure.
	FailureUnknown ExecutorCommitmentFailure = 1
	// FailureStateUnavailable indicates that batch processing failed due to the state being
	// unavailable.
	FailureStateUnavailable ExecutorCommitmentFailure = 2
)

// ComputeBody holds the data signed in a compute worker commitment.
type ComputeBody struct {
	Header  ComputeResultsHeader      `json:"header"`
	Failure ExecutorCommitmentFailure `json:"failure,omitempty"`

	// Fields from the proposal.

	ProposalSignature signature.Signature `json:"proposal_sig"`
	BatchHash         hash.Hash           `json:"batch_hash"`

	// Optional fields (may be absent for failure indication).

	RakSig   *signature.RawSignature `json:"rak_sig,omitempty"`
	Messages []message.Message       `json:"messages,omitempty"`
}

// SetFailure sets failure reason and clears any fields that should be clear
// in a failure indicating commitment.
func (m *ComputeBody) SetFailure(failure ExecutorCommitmentFailure) {
	m.Header.IORoot = nil
	m.Header.StateRoot = nil
	m.Header.MessagesHash = nil
	m.RakSig = nil
	m.Messages = nil
	m.Failure = failure
}

// VerifyProposalSignature rebuilds the proposal header from the data in the ComputeBody struct and
// verifies that the transaction scheduler signature matches what we're seeing.
func (m *ComputeBody) VerifyProposalSignature(runtimeID common.Namespace, header block.Header) (bool, error) {
	sigCtx, err := ProposalSignatureContext.WithSuffix(runtimeID.String())
	if err != nil {
		return false, fmt.Errorf("proposed batch signature context error: %w", err)
	}
	proposalHeader := &ProposalHeader{
		PreviousHeader: header,
		BatchHash:      m.BatchHash,
	}
	return m.ProposalSignature.Verify(sigCtx, cbor.Marshal(proposalHeader)), nil
}

// ValidateBasic performs basic executor commitment validity checks.
func (m *ComputeBody) ValidateBasic() error {
	header := &m.Header
	switch m.Failure {
	case FailureNone:
		// Ensure header fields are present.
		if header.IORoot == nil {
			return fmt.Errorf("missing IORoot")
		}
		if header.StateRoot == nil {
			return fmt.Errorf("missing StateRoot")
		}
		if header.MessagesHash == nil {
			return fmt.Errorf("missing messages hash")
		}

		// Validate any included runtime messages.
		for i, msg := range m.Messages {
			if err := msg.ValidateBasic(); err != nil {
				return fmt.Errorf("bad runtime message %d: %w", i, err)
			}
		}
	case FailureUnknown, FailureStateUnavailable:
		// Ensure header fields are empty.
		if header.IORoot != nil {
			return fmt.Errorf("failure indicating body includes IORoot")
		}
		if header.StateRoot != nil {
			return fmt.Errorf("failure indicating commitment includes StateRoot")
		}
		if header.MessagesHash != nil {
			return fmt.Errorf("failure indicating commitment includes MessagesHash")
		}
		// In case of failure indicating commitment make sure RAK signature is empty.
		if m.RakSig != nil {
			return fmt.Errorf("failure indicating body includes RAK signature")
		}
		// In case of failure indicating commitment make sure messages are empty.
		if len(m.Messages) > 0 {
			return fmt.Errorf("failure indicating body includes messages")
		}
	default:
		return fmt.Errorf("invalid failure: %d", m.Failure)
	}

	return nil
}

// ExecutorCommitment is a roothash commitment from an executor worker.
//
// The signed content is ComputeBody.
type ExecutorCommitment struct {
	signature.Signed
}

// Equal compares vs another ExecutorCommitment for equality.
func (c *ExecutorCommitment) Equal(cmp *ExecutorCommitment) bool {
	return c.Signed.Equal(&cmp.Signed)
}

// OpenExecutorCommitment is an executor commitment that has been verified and
// deserialized.
//
// The open commitment still contains the original signed commitment.
type OpenExecutorCommitment struct {
	ExecutorCommitment

	Body *ComputeBody `json:"-"` // No need to serialize as it can be reconstructed.
}

// UnmarshalCBOR handles CBOR unmarshalling from passed data.
func (c *OpenExecutorCommitment) UnmarshalCBOR(data []byte) error {
	if err := cbor.Unmarshal(data, &c.ExecutorCommitment); err != nil {
		return err
	}

	c.Body = new(ComputeBody)
	return cbor.Unmarshal(c.Blob, c.Body)
}

// MostlyEqual returns true if the commitment is mostly equal to another
// specified commitment as per discrepancy detection criteria.
func (c OpenExecutorCommitment) MostlyEqual(other OpenCommitment) bool {
	h := c.Body.Header.EncodedHash()
	otherHash := other.(OpenExecutorCommitment).Body.Header.EncodedHash()
	return h.Equal(&otherHash)
}

// IsIndicatingFailure returns true if this commitment indicates a failure.
func (c OpenExecutorCommitment) IsIndicatingFailure() bool {
	return c.Body.Failure != FailureNone
}

// ToVote returns a hash that represents a vote for this commitment as
// per discrepancy resolution criteria.
func (c OpenExecutorCommitment) ToVote() hash.Hash {
	return c.Body.Header.EncodedHash()
}

// ToDDResult returns a commitment-specific result after discrepancy
// detection.
func (c OpenExecutorCommitment) ToDDResult() interface{} {
	return c.Body
}

// Open validates the executor commitment signature, and de-serializes the message.
// This does not validate the RAK signature.
func (c *ExecutorCommitment) Open(runtimeID common.Namespace) (*OpenExecutorCommitment, error) {
	sigCtx, err := ExecutorSignatureContext.WithSuffix(runtimeID.String())
	if err != nil {
		return nil, fmt.Errorf("roothash/commitment: signature context error: %w", err)
	}

	var body ComputeBody
	if err := c.Signed.Open(sigCtx, &body); err != nil {
		return nil, errors.New("roothash/commitment: commitment has invalid signature")
	}

	return &OpenExecutorCommitment{
		ExecutorCommitment: *c,
		Body:               &body,
	}, nil
}

// SignExecutorCommitment serializes the message and signs the commitment.
func SignExecutorCommitment(
	signer signature.Signer,
	runtimeID common.Namespace,
	body *ComputeBody,
) (*ExecutorCommitment, error) {
	sigCtx, err := ExecutorSignatureContext.WithSuffix(runtimeID.String())
	if err != nil {
		return nil, fmt.Errorf("roothash/commitment: signature context error: %w", err)
	}

	signed, err := signature.SignSigned(signer, sigCtx, body)
	if err != nil {
		return nil, err
	}

	return &ExecutorCommitment{
		Signed: *signed,
	}, nil
}
