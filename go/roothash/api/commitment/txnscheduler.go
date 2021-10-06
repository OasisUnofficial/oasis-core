package commitment

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

// ProposalSignatureContext is the context used for signing propose batch dispatch messages.
var ProposalSignatureContext = signature.NewContext(
	"oasis-core/roothash: proposal",
	signature.WithChainSeparation(),
	signature.WithDynamicSuffix(" for runtime ", common.NamespaceHexSize),
)

// ProposalHeader is the header of the batch proposal.
type ProposalHeader struct {
	// PreviousHeader is the block header on which the batch should be based.
	PreviousHeader block.Header `json:"previous_header"`

	// BatchHash is the hash of the content of the batch.
	BatchHash hash.Hash `json:"batch_hash"`
}

// Sign signs the proposal header.
func (ph *ProposalHeader) Sign(signer signature.Signer) (*SignedProposalHeader, error) {
	sigCtx, err := ProposalSignatureContext.WithSuffix(ph.PreviousHeader.Namespace.String())
	if err != nil {
		return nil, fmt.Errorf("signature context error: %w", err)
	}
	signed, err := signature.SignSigned(signer, sigCtx, ph)
	if err != nil {
		return nil, err
	}
	return &SignedProposalHeader{Signed: *signed}, nil
}

type SignedProposalHeader struct {
	signature.Signed
}

// Equal compares vs another SignedProposalHeader for equality.
func (sp *SignedProposalHeader) Equal(cmp *SignedProposalHeader) bool {
	return sp.Signed.Equal(&cmp.Signed)
}

// Open first verifies the signed prpoposal header and then unmarshals it.
func (sp *SignedProposalHeader) Open(runtimeID common.Namespace, header *ProposalHeader) error {
	sigCtx, err := ProposalSignatureContext.WithSuffix(runtimeID.String())
	if err != nil {
		return fmt.Errorf("signature context error: %w", err)
	}
	return sp.Signed.Open(sigCtx, header)
}

// Proposal is a batch proposal.
type Proposal struct {
	// SignedProposalHeader is the proposal header signed by the transaction scheduler.
	SignedProposalHeader SignedProposalHeader `json:"header"`

	// Batch is an ordered list of all transaction hashes that should be in a batch.
	Batch []hash.Hash `json:"batch,omitempty"`
}

// GetTransactionScheduler returns the transaction scheduler of the provided
// committee based on the provided round.
func GetTransactionScheduler(committee *scheduler.Committee, round uint64) (*scheduler.CommitteeNode, error) {
	workers := committee.Workers()
	numNodes := uint64(len(workers))
	if numNodes == 0 {
		return nil, fmt.Errorf("GetTransactionScheduler: no workers in commmittee")
	}
	schedulerIdx := round % numNodes
	return workers[schedulerIdx], nil
}
