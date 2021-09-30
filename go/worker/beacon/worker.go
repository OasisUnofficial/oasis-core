// Package beacon implements the random beacon worker.
package beacon

import (
	"context"
	"fmt"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
)

const workerName = "worker/beacon"

type Worker struct {
	pvss *pvssWorker

	ctx context.Context

	identity  *identity.Identity
	consensus consensus.Backend

	allQuitCh chan struct{}
	allQuitWg sync.WaitGroup
}

func (w *Worker) Start() error {
	if w.pvss != nil {
		if err := w.pvss.Start(); err != nil {
			return fmt.Errorf("worker/beacon: failed to start PVSS worker: %w", err)
		}
	}

	return nil
}

func (w *Worker) Stop() {
	if w.pvss != nil {
		w.pvss.Stop()
	}
}

func (w *Worker) Quit() <-chan struct{} {
	return w.allQuitCh
}

func (w *Worker) Cleanup() {
	if w.pvss != nil {
		w.pvss.Cleanup()
	}
}

func (w *Worker) Name() string {
	return "beacon worker"
}

// New creates a new worker instance.
func New(
	identity *identity.Identity,
	consensus consensus.Backend,
	store *persistent.CommonStore,
) (*Worker, error) {
	var (
		err     error
		created bool
	)
	w := &Worker{
		ctx:       context.Background(),
		identity:  identity,
		consensus: consensus,
		allQuitCh: make(chan struct{}),
	}

	initLogger := logging.GetLogger(workerName)

	if w.pvss, err = newPVSS(w, store); err == nil {
		w.allQuitWg.Add(1)
		go func() {
			defer w.allQuitWg.Done()
			<-w.pvss.Quit()
		}()

		created = true
	} else {
		initLogger.Error("failed to initialize PVSS worker",
			"err", err,
		)
	}

	if created {
		go func() {
			defer close(w.allQuitCh)
			w.allQuitWg.Wait()
		}()
	} else {
		close(w.allQuitCh)
		return nil, fmt.Errorf("worker/beacon: failed to create any workers")
	}

	return w, nil
}
