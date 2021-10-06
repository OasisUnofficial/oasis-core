package api

import (
	"context"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
)

var (
	storageFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oasis_storage_failures",
			Help: "Number of storage failures.",
		},
		[]string{"call"},
	)
	storageCalls = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oasis_storage_successes",
			Help: "Number of storage successes.",
		},
		[]string{"call"},
	)
	storageLatency = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "oasis_storage_latency",
			Help: "Storage call latency (seconds).",
		},
		[]string{"call"},
	)
	storageValueSize = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "oasis_storage_value_size",
			Help: "Storage call value size (bytes).",
		},
		[]string{"call"},
	)

	storageCollectors = []prometheus.Collector{
		storageFailures,
		storageCalls,
		storageLatency,
		storageValueSize,
	}

	labelSyncGet         = prometheus.Labels{"call": "sync_get"}
	labelSyncGetPrefixes = prometheus.Labels{"call": "sync_get_prefixes"}
	labelSyncIterate     = prometheus.Labels{"call": "sync_iterate"}

	_ LocalBackend  = (*metricsWrapper)(nil)
	_ ClientBackend = (*metricsWrapper)(nil)

	metricsOnce sync.Once
)

type metricsWrapper struct {
	Backend
}

func (w *metricsWrapper) GetConnectedNodes() []*node.Node {
	if clientBackend, ok := w.Backend.(ClientBackend); ok {
		return clientBackend.GetConnectedNodes()
	}
	return []*node.Node{}
}

func (w *metricsWrapper) EnsureCommitteeVersion(ctx context.Context, version int64) error {
	if clientBackend, ok := w.Backend.(ClientBackend); ok {
		return clientBackend.EnsureCommitteeVersion(ctx, version)
	}
	return ErrUnsupported
}

func (w *metricsWrapper) SyncGet(ctx context.Context, request *GetRequest) (*ProofResponse, error) {
	start := time.Now()
	res, err := w.Backend.SyncGet(ctx, request)
	storageLatency.With(labelSyncGet).Observe(time.Since(start).Seconds())
	if err != nil {
		storageFailures.With(labelSyncGet).Inc()
		return nil, err
	}

	storageCalls.With(labelSyncGet).Inc()
	return res, err
}

func (w *metricsWrapper) SyncGetPrefixes(ctx context.Context, request *GetPrefixesRequest) (*ProofResponse, error) {
	start := time.Now()
	res, err := w.Backend.SyncGetPrefixes(ctx, request)
	storageLatency.With(labelSyncGetPrefixes).Observe(time.Since(start).Seconds())
	if err != nil {
		storageFailures.With(labelSyncGetPrefixes).Inc()
		return nil, err
	}

	storageCalls.With(labelSyncGetPrefixes).Inc()
	return res, err
}

func (w *metricsWrapper) SyncIterate(ctx context.Context, request *IterateRequest) (*ProofResponse, error) {
	start := time.Now()
	res, err := w.Backend.SyncIterate(ctx, request)
	storageLatency.With(labelSyncIterate).Observe(time.Since(start).Seconds())
	if err != nil {
		storageFailures.With(labelSyncIterate).Inc()
		return nil, err
	}

	storageCalls.With(labelSyncIterate).Inc()
	return res, err
}

func (w *metricsWrapper) Apply(ctx context.Context, request *ApplyRequest) error {
	localBackend, ok := w.Backend.(LocalBackend)
	if !ok {
		return nil
	}
	return localBackend.Apply(ctx, request)
}

func (w *metricsWrapper) Checkpointer() checkpoint.CreateRestorer {
	localBackend, ok := w.Backend.(LocalBackend)
	if !ok {
		return nil
	}
	return localBackend.Checkpointer()
}

func (w *metricsWrapper) NodeDB() NodeDB {
	localBackend, ok := w.Backend.(LocalBackend)
	if !ok {
		return nil
	}
	return localBackend.NodeDB()
}

func NewMetricsWrapper(base Backend) LocalBackend {
	metricsOnce.Do(func() {
		prometheus.MustRegister(storageCollectors...)
	})

	w := &metricsWrapper{Backend: base}

	return w
}
