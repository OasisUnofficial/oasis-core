package scheduler

import (
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"sync"

	beacon "github.com/oasislabs/ekiden/go/beacon/api"
	"github.com/oasislabs/ekiden/go/common/contract"
	"github.com/oasislabs/ekiden/go/common/crypto/drbg"
	"github.com/oasislabs/ekiden/go/common/crypto/mathrand"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/registry"

	"github.com/eapache/channels"
)

var (
	_ Scheduler = (*TrivialScheduler)(nil)

	rngContextCompute = []byte("EkS-Dummy-Compute")
	rngContextStorage = []byte("EkS-Dummy-Storage")
)

// TrivialScheduler is a basic scheduler.
type TrivialScheduler struct {
	logger *logging.Logger

	state *trivialSchedulerState

	notifier *pubsub.Broker
}

type trivialSchedulerState struct {
	sync.RWMutex

	nodeLists  map[epochtime.EpochTime][]*node.Node
	beacons    map[epochtime.EpochTime][]byte
	contracts  map[signature.MapKey]*contract.Contract
	committees map[epochtime.EpochTime]map[signature.MapKey][]*Committee

	epoch     epochtime.EpochTime
	lastElect epochtime.EpochTime
}

func (s *trivialSchedulerState) canElect() bool {
	return s.nodeLists[s.epoch] != nil && s.beacons[s.epoch] != nil
}

func (s *trivialSchedulerState) elect(con *contract.Contract, notifier *pubsub.Broker) error { //nolint:gocyclo
	var committees []*Committee

	nodeList := s.nodeLists[s.epoch]
	beacon := s.beacons[s.epoch]

	for _, kind := range []CommitteeKind{Compute, Storage} {
		var sz int
		var ctx []byte
		switch kind {
		case Compute:
			sz = int(con.ReplicaGroupSize + con.ReplicaGroupBackupSize)
			ctx = rngContextCompute
		case Storage:
			sz = int(con.StorageGroupSize)
			ctx = rngContextStorage
		default:
			return fmt.Errorf("scheduler: invalid committee type: %v", kind)
		}

		if sz == 0 {
			return errors.New("scheduler: empty committee not allowed")
		}
		if sz > len(nodeList) {
			return errors.New("scheduler: committee size exceeds available nodes")
		}

		drbg, err := drbg.New(crypto.SHA512, beacon, nil, ctx)
		if err != nil {
			return err
		}
		rngSrc := mathrand.New(drbg)
		rng := rand.New(rngSrc)
		idxs := rng.Perm(sz)

		committee := &Committee{
			Kind:     kind,
			Contract: con,
			ValidFor: s.epoch,
		}

		for i := 0; i < sz; i++ {
			var role Role
			switch {
			case i == 0:
				role = Leader
			case i > int(con.ReplicaGroupSize):
				role = BackupWorker
			default:
				role = Worker
			}
			committee.Members = append(committee.Members, &CommitteeNode{
				Role:      role,
				PublicKey: nodeList[idxs[i]].ID,
			})
		}

		committees = append(committees, committee)
	}

	s.Lock()
	defer s.Unlock()

	if s.committees[s.epoch] == nil {
		s.committees[s.epoch] = make(map[signature.MapKey][]*Committee)
	}
	comMap := s.committees[s.epoch]
	comMap[con.ID.ToMapKey()] = committees
	for _, committee := range committees {
		notifier.Broadcast(committee)
	}

	return nil
}

func (s *trivialSchedulerState) prune() {
	pruneBefore := s.epoch - 1

	for epoch := range s.nodeLists {
		if epoch < pruneBefore {
			delete(s.nodeLists, epoch)
		}
	}
	for epoch := range s.beacons {
		if epoch < pruneBefore {
			delete(s.beacons, epoch)
		}
	}

	s.Lock()
	defer s.Unlock()

	for epoch := range s.committees {
		if epoch < pruneBefore {
			delete(s.committees, epoch)
		}
	}
}

func (s *trivialSchedulerState) updateEpoch(epoch epochtime.EpochTime) {
	s.Lock()
	defer s.Unlock()

	s.epoch = epoch
}

func (s *trivialSchedulerState) updateLastElect() {
	s.Lock()
	defer s.Unlock()

	s.lastElect = s.epoch
}

// GetCommittees returns a vector of the committees for a given contract
// ID, for the current epoch.
func (s *TrivialScheduler) GetCommittees(id signature.PublicKey) []*Committee {
	s.state.RLock()
	defer s.state.RUnlock()

	comMap := s.state.committees[s.state.epoch]
	if comMap == nil {
		return nil
	}
	return comMap[id.ToMapKey()]
}

// WatchCommittees returns a channel that produces a stream of Committee.
//
// Upon subscription, all committees for the current epoch will be
// sent immediately.
func (s *TrivialScheduler) WatchCommittees() (<-chan *Committee, *pubsub.Subscription) {
	return subscribeTypedCommittee(s.notifier)
}

func (s *TrivialScheduler) worker(timeSource epochtime.Backend, conReg registry.ContractRegistry, entReg registry.EntityRegistry, beacon beacon.Backend) { //nolint:gocyclo
	timeCh, sub := timeSource.WatchEpochs()
	defer sub.Close()

	contractCh, sub := conReg.WatchContracts()
	defer sub.Close()

	nodeListCh, sub := entReg.WatchNodeList()
	defer sub.Close()

	beaconCh, sub := beacon.WatchBeacons()
	defer sub.Close()

	for {
		select {
		case epoch := <-timeCh:
			if epoch == s.state.epoch {
				continue
			}
			s.logger.Debug("worker: epoch transition",
				"prev_epoch", s.state.epoch,
				"epoch", epoch,
			)
			s.state.updateEpoch(epoch)
			s.state.prune()
		case ev := <-nodeListCh:
			if s.state.nodeLists[ev.Epoch] != nil {
				s.logger.Error("worker: node list when already received",
					"epoch", ev.Epoch,
				)
				continue
			}
			s.logger.Debug("worker: node list for epoch",
				"epoch", ev.Epoch,
			)
			s.state.nodeLists[ev.Epoch] = ev.Nodes
		case ev := <-beaconCh:
			if b := s.state.beacons[ev.Epoch]; b != nil {
				s.logger.Error("worker: beacon when already received",
					"epoch", ev.Epoch,
					"beacon", hex.EncodeToString(b),
					"new_beacon", hex.EncodeToString(ev.Beacon),
				)
				continue
			}
			s.logger.Debug("worker: beacon for epoch",
				"epoch", ev.Epoch,
				"beacon", hex.EncodeToString(ev.Beacon),
			)
			s.state.beacons[ev.Epoch] = ev.Beacon
		case contract := <-contractCh:
			mk := contract.ID.ToMapKey()
			if con := s.state.contracts[mk]; con != nil {
				s.logger.Error("worker: contract registration ID conflict",
					"contract", con,
					"new_contract", contract,
				)
				continue
			}
			s.state.contracts[mk] = contract
			if s.state.epoch == s.state.lastElect && s.state.canElect() {
				// Attempt to elect the committee if possible, since
				// the election for the epoch happened already.
				if err := s.state.elect(contract, s.notifier); err != nil {
					s.logger.Debug("worker: failed to elect (single)",
						"contract", contract,
						"err", err,
					)
				}
				s.logger.Debug("worker: election (single)",
					"contract", contract,
					"committees", s.state.committees[s.state.epoch][contract.ID.ToMapKey()],
				)
			}
			continue
		}

		if s.state.epoch == s.state.lastElect || !s.state.canElect() {
			continue
		}

		// Elect ALL THE THINGS. \o/
		s.logger.Debug("worker: electing for epoch",
			"epoch", s.state.epoch,
		)

		for _, v := range s.state.contracts {
			if err := s.state.elect(v, s.notifier); err != nil {
				s.logger.Debug("worker: failed to elect",
					"contract", v,
					"err", err,
				)
			}
			s.logger.Debug("worker: election",
				"contract", v,
				"committees", s.state.committees[s.state.epoch][v.ID.ToMapKey()],
			)
		}

		s.state.updateLastElect()
	}
}

// NewTrivialScheduler returns a new TrivialScheduler instance.
func NewTrivialScheduler(timeSource epochtime.Backend, conReg registry.ContractRegistry, entReg registry.EntityRegistry, beacon beacon.Backend) *TrivialScheduler {
	s := &TrivialScheduler{
		logger: logging.GetLogger("TrivialScheudler"),
		state: &trivialSchedulerState{
			nodeLists:  make(map[epochtime.EpochTime][]*node.Node),
			beacons:    make(map[epochtime.EpochTime][]byte),
			contracts:  make(map[signature.MapKey]*contract.Contract),
			committees: make(map[epochtime.EpochTime]map[signature.MapKey][]*Committee),
			epoch:      epochtime.EpochInvalid,
			lastElect:  epochtime.EpochInvalid,
		},
	}
	s.notifier = pubsub.NewBrokerEx(func(ch *channels.InfiniteChannel) {
		s.state.RLock()
		defer s.state.RUnlock()

		if s.state.lastElect != s.state.epoch {
			// A mass-election will happen Real Soon Now, don't bother.
			return
		}

		comMap := s.state.committees[s.state.epoch]
		if comMap == nil {
			return
		}

		for _, v := range comMap {
			for _, vv := range v {
				s.notifier.Broadcast(vv)
			}
		}
	})

	go s.worker(timeSource, conReg, entReg, beacon)

	return s
}
