// Package keymanager implements the key manager worker.
package keymanager

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/service"
	"github.com/oasisprotocol/oasis-core/go/config"
	"github.com/oasisprotocol/oasis-core/go/keymanager/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	workerCommon "github.com/oasisprotocol/oasis-core/go/worker/common"
	committeeCommon "github.com/oasisprotocol/oasis-core/go/worker/common/committee"
	workerKeymanager "github.com/oasisprotocol/oasis-core/go/worker/keymanager/api"
	"github.com/oasisprotocol/oasis-core/go/worker/keymanager/p2p"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
)

// New constructs a new key manager worker.
func New(
	commonWorker *workerCommon.Worker,
	r *registration.Worker,
	keymanager api.Backend,
	provisioner host.Provisioner,
) (*Worker, error) {
	var enabled bool
	switch config.GlobalConfig.Mode {
	case config.ModeKeyManager:
		// When configured in keymanager mode, enable the keymanager worker.
		enabled = true
	default:
		enabled = false
	}

	ctx, cancelFn := context.WithCancel(context.Background())

	w := &Worker{
		logger:       logging.GetLogger("worker/keymanager"),
		ctx:          ctx,
		cancelCtx:    cancelFn,
		quitCh:       make(chan struct{}),
		initCh:       make(chan struct{}),
		nodeID:       commonWorker.Identity.NodeSigner.Public(),
		peerMap:      NewPeerMap(),
		accessList:   NewAccessList(),
		commonWorker: commonWorker,
		keymanager:   keymanager,
		enabled:      enabled,
	}

	if !w.enabled {
		return w, nil
	}

	initMetrics()

	// Parse runtime ID.
	if err := w.runtimeID.UnmarshalHex(config.GlobalConfig.Keymanager.RuntimeID); err != nil {
		return nil, fmt.Errorf("worker/keymanager: failed to parse runtime ID: %w", err)
	}
	w.runtimeLabel = w.runtimeID.String()

	var err error
	w.roleProvider, err = r.NewRuntimeRoleProvider(node.RoleKeyManager, w.runtimeID)
	if err != nil {
		return nil, fmt.Errorf("worker/keymanager: failed to create role provider: %w", err)
	}

	w.runtime, err = commonWorker.RuntimeRegistry.GetRuntime(w.runtimeID)
	if err != nil {
		return nil, fmt.Errorf("worker/keymanager: failed to get runtime: %w", err)
	}

	// Prepare key manager client.
	w.keyManagerClient = committeeCommon.NewKeyManagerClientWrapper(w.commonWorker.P2P, w.commonWorker.Consensus, w.commonWorker.ChainContext, w.logger)
	w.keyManagerClient.SetKeyManagerID(&w.runtimeID)

	// Prepare the runtime host handler.
	handler := runtimeRegistry.NewRuntimeHostHandler(&workerEnvironment{w}, w.runtime, w.commonWorker.Consensus)

	// Prepare the runtime host node helpers.
	w.RuntimeHostNode, err = runtimeRegistry.NewRuntimeHostNode(w.runtime, provisioner, handler, w.commonWorker.RuntimeRegistry.GetLogManager())
	if err != nil {
		return nil, fmt.Errorf("worker/keymanager: failed to create runtime host helpers: %w", err)
	}

	// Prepare the runtime host notifier.
	host := w.GetHostedRuntime()
	notifier := runtimeRegistry.NewRuntimeHostNotifier(host)
	lbNotifier := runtimeRegistry.NewLightBlockNotifier(w.runtime, host, commonWorker.Consensus, notifier)

	// Prepare services to run.
	w.services = service.NewGroup(notifier, lbNotifier)

	// Prepare watchers.
	w.kmNodeWatcher = newKmNodeWatcher(w.runtimeID, commonWorker.Consensus, w.peerMap, w.accessList, w.commonWorker.P2P.PeerManager().PeerTagger())
	w.kmRuntimeWatcher = newKmRuntimeWatcher(w.runtimeID, commonWorker.Consensus, w.accessList)

	// Prepare sub-workers.
	w.secretsWorker, err = newSecretsWorker(w.runtimeID, commonWorker, w, r, keymanager)
	if err != nil {
		return nil, fmt.Errorf("worker/keymanager: failed to create secrets worker: %w", err)
	}
	w.churpWorker, err = newChurpWorker(w)
	if err != nil {
		return nil, fmt.Errorf("worker/keymanager: failed to create churp worker: %w", err)
	}

	// Prepare access controllers and register their methods.
	w.accessControllers = []workerKeymanager.RPCAccessController{
		w.secretsWorker,
		w.churpWorker,
	}
	w.accessControllersByMethod = make(map[string]workerKeymanager.RPCAccessController)
	for _, ctrl := range w.accessControllers {
		for _, m := range ctrl.Methods() {
			if _, ok := w.accessControllersByMethod[m]; ok {
				return nil, fmt.Errorf("worker/keymanager: duplicate enclave RPC method: %s", m)
			}
			w.accessControllersByMethod[m] = ctrl
		}
	}

	// Register keymanager service.
	commonWorker.P2P.RegisterProtocolServer(p2p.NewServer(commonWorker.ChainContext, w.runtimeID, w))

	return w, nil
}
