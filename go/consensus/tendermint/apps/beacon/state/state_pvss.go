package state

import (
	"context"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/keyformat"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
)

// pvssStateKeyFmt is the current PVSS round key format.
var pvssStateKeyFmt = keyformat.New(0x44)

func (s *ImmutableState) PVSSState(ctx context.Context) (*beacon.PVSSState, error) {
	data, err := s.is.Get(ctx, pvssStateKeyFmt.Encode())
	if err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	if data == nil {
		return nil, nil
	}

	var state beacon.PVSSState
	if err = cbor.Unmarshal(data, &state); err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	return &state, nil
}

func (s *MutableState) SetPVSSState(ctx context.Context, state *beacon.PVSSState) error {
	err := s.ms.Insert(ctx, pvssStateKeyFmt.Encode(), cbor.Marshal(state))
	return abciAPI.UnavailableStateError(err)
}

func (s *MutableState) ClearPVSSState(ctx context.Context) error {
	err := s.ms.Remove(ctx, pvssStateKeyFmt.Encode())
	return abciAPI.UnavailableStateError(err)
}
