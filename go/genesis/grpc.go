package genesis

import (
	"context"
	"encoding/json"
	"time"

	"google.golang.org/grpc"

	"github.com/oasislabs/oasis-core/go/genesis/api"
	pb "github.com/oasislabs/oasis-core/go/grpc/genesis"
	keymanager "github.com/oasislabs/oasis-core/go/keymanager/api"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	roothash "github.com/oasislabs/oasis-core/go/roothash/api"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
	"github.com/oasislabs/oasis-core/go/tendermint/service"
)

var (
	_ pb.GenesisServer = (*grpcServer)(nil)
)

type grpcServer struct {
	tendermintService service.TendermintService

	keymanagerBackend keymanager.Backend
	registryBackend   registry.Backend
	roothashBackend   roothash.Backend
	stakingBackend    staking.Backend
}

// ToGenesis generates a genesis document based on current state at given height.
func (s *grpcServer) ToGenesis(ctx context.Context, req *pb.GenesisRequest) (*pb.GenesisResponse, error) {
	height := req.GetHeight()
	if height <= 0 {
		var err error
		if height, err = s.tendermintService.GetHeight(); err != nil {
			return nil, err
		}
	}

	// Get genesis doc.
	genesisProvider, err := New()
	if err != nil {
		return nil, err
	}
	genesisDoc, err := genesisProvider.GetGenesisDocument()
	if err != nil {
		return nil, err
	}

	// Call ToGenesis on all backends and merge the results together.
	registryGenesis, err := s.registryBackend.ToGenesis(ctx, height)
	if err != nil {
		return nil, err
	}
	roothashGenesis, err := s.roothashBackend.ToGenesis(ctx, height)
	if err != nil {
		return nil, err
	}
	stakingGenesis, err := s.stakingBackend.ToGenesis(ctx, height)
	if err != nil {
		return nil, err
	}
	keymanagerGenesis, err := s.keymanagerBackend.ToGenesis(ctx, height)
	if err != nil {
		return nil, err
	}

	doc := api.Document{
		// XXX: Tendermint doesn't support restoring from non-0 height.
		// https://github.com/tendermint/tendermint/issues/2543
		Height:     0,
		ChainID:    genesisDoc.ChainID,
		Time:       time.Now(),
		Registry:   *registryGenesis,
		RootHash:   *roothashGenesis,
		Staking:    *stakingGenesis,
		KeyManager: *keymanagerGenesis,
	}

	// Return final genesis document as JSON.
	b, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	resp := pb.GenesisResponse{
		Json: b,
	}
	return &resp, nil
}

func NewGRPCServer(grpc *grpc.Server, tm service.TendermintService, km keymanager.Backend, reg registry.Backend, rh roothash.Backend, s staking.Backend) {
	srv := &grpcServer{
		tendermintService: tm,
		keymanagerBackend: km,
		registryBackend:   reg,
		roothashBackend:   rh,
		stakingBackend:    s,
	}
	pb.RegisterGenesisServer(grpc, srv)
}
