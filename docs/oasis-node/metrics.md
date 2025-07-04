---
# DO NOT EDIT. This file was generated by extract-metrics
---

# Metrics

`oasis-node` can report a number of metrics to Prometheus server. By default,
no metrics are collected and reported. There is one way to enable metrics
reporting:

* *Pull mode* listens on given address and waits for Prometheus to scrape the
  metrics.

## Configuring `oasis-node` in Pull Mode

To run `oasis-node` in *pull mode* with Prometheus metrics enabled, add the
following to your `config.yml`.

```
metrics:
  mode: pull
  address: 0.0.0.0:3000
```

After restarting the node, Prometheus metrics will be exposed on port 3000.

Then, add the following segment to your `prometheus.yml` and restart
Prometheus:

```yaml
  - job_name : 'oasis-node'

    scrape_interval: 5s

    static_configs:
      - targets: ['localhost:3000']
```

## Metrics Reported by `oasis-node`

`oasis-node` reports metrics starting with `oasis_`.

The following metrics are currently reported:

<!-- markdownlint-disable line-length -->

Name | Type | Description | Labels | Package
-----|------|-------------|--------|--------
oasis_abci_db_size | Gauge | Total size of the ABCI database (MiB). |  | [consensus/cometbft/abci](https://github.com/oasisprotocol/oasis-core/tree/master/go/consensus/cometbft/abci/mux.go)
oasis_codec_size | Summary | CBOR codec message size (bytes). | call, module | [common/cbor](https://github.com/oasisprotocol/oasis-core/tree/master/go/common/cbor/codec.go)
oasis_consensus_proposed_blocks | Counter | Number of blocks proposed by the node. | backend | [consensus/metrics](https://github.com/oasisprotocol/oasis-core/tree/master/go/consensus/metrics/metrics.go)
oasis_consensus_signed_blocks | Counter | Number of blocks signed by the node. | backend | [consensus/metrics](https://github.com/oasisprotocol/oasis-core/tree/master/go/consensus/metrics/metrics.go)
oasis_finalized_rounds | Counter | Number of finalized rounds. |  | [roothash](https://github.com/oasisprotocol/oasis-core/tree/master/go/roothash/metrics.go)
oasis_grpc_client_calls | Counter | Number of gRPC calls. | call | [common/grpc](https://github.com/oasisprotocol/oasis-core/tree/master/go/common/grpc/grpc.go)
oasis_grpc_client_latency | Summary | gRPC call latency (seconds). | call | [common/grpc](https://github.com/oasisprotocol/oasis-core/tree/master/go/common/grpc/grpc.go)
oasis_grpc_client_stream_writes | Counter | Number of gRPC stream writes. | call | [common/grpc](https://github.com/oasisprotocol/oasis-core/tree/master/go/common/grpc/grpc.go)
oasis_grpc_server_calls | Counter | Number of gRPC calls. | call | [common/grpc](https://github.com/oasisprotocol/oasis-core/tree/master/go/common/grpc/grpc.go)
oasis_grpc_server_latency | Summary | gRPC call latency (seconds). | call | [common/grpc](https://github.com/oasisprotocol/oasis-core/tree/master/go/common/grpc/grpc.go)
oasis_grpc_server_stream_writes | Counter | Number of gRPC stream writes. | call | [common/grpc](https://github.com/oasisprotocol/oasis-core/tree/master/go/common/grpc/grpc.go)
oasis_node_cpu_stime_seconds | Gauge | CPU system time spent by worker as reported by /proc/&lt;PID&gt;/stat (seconds). |  | [oasis-node/cmd/common/metrics](https://github.com/oasisprotocol/oasis-core/tree/master/go/oasis-node/cmd/common/metrics/cpu.go)
oasis_node_cpu_utime_seconds | Gauge | CPU user time spent by worker as reported by /proc/&lt;PID&gt;/stat (seconds). |  | [oasis-node/cmd/common/metrics](https://github.com/oasisprotocol/oasis-core/tree/master/go/oasis-node/cmd/common/metrics/cpu.go)
oasis_node_disk_read_bytes | Gauge | Read data from block storage by the worker as reported by /proc/&lt;PID&gt;/io (bytes). |  | [oasis-node/cmd/common/metrics](https://github.com/oasisprotocol/oasis-core/tree/master/go/oasis-node/cmd/common/metrics/disk.go)
oasis_node_disk_usage_bytes | Gauge | Size of datadir of the worker (bytes). |  | [oasis-node/cmd/common/metrics](https://github.com/oasisprotocol/oasis-core/tree/master/go/oasis-node/cmd/common/metrics/disk.go)
oasis_node_disk_written_bytes | Gauge | Written data from block storage by the worker as reported by /proc/&lt;PID&gt;/io (bytes) |  | [oasis-node/cmd/common/metrics](https://github.com/oasisprotocol/oasis-core/tree/master/go/oasis-node/cmd/common/metrics/disk.go)
oasis_node_mem_rss_anon_bytes | Gauge | Size of resident anonymous memory of worker as reported by /proc/&lt;PID&gt;/status (bytes). |  | [oasis-node/cmd/common/metrics](https://github.com/oasisprotocol/oasis-core/tree/master/go/oasis-node/cmd/common/metrics/mem.go)
oasis_node_mem_rss_file_bytes | Gauge | Size of resident file mappings of worker as reported by /proc/&lt;PID&gt;/status (bytes) |  | [oasis-node/cmd/common/metrics](https://github.com/oasisprotocol/oasis-core/tree/master/go/oasis-node/cmd/common/metrics/mem.go)
oasis_node_mem_rss_shmem_bytes | Gauge | Size of resident shared memory of worker. |  | [oasis-node/cmd/common/metrics](https://github.com/oasisprotocol/oasis-core/tree/master/go/oasis-node/cmd/common/metrics/mem.go)
oasis_node_mem_vm_size_bytes | Gauge | Virtual memory size of worker (bytes). |  | [oasis-node/cmd/common/metrics](https://github.com/oasisprotocol/oasis-core/tree/master/go/oasis-node/cmd/common/metrics/mem.go)
oasis_node_net_receive_bytes_total | Gauge | Received data for each network device as reported by /proc/net/dev (bytes). | device | [oasis-node/cmd/common/metrics](https://github.com/oasisprotocol/oasis-core/tree/master/go/oasis-node/cmd/common/metrics/net.go)
oasis_node_net_receive_packets_total | Gauge | Received data for each network device as reported by /proc/net/dev (packets). | device | [oasis-node/cmd/common/metrics](https://github.com/oasisprotocol/oasis-core/tree/master/go/oasis-node/cmd/common/metrics/net.go)
oasis_node_net_transmit_bytes_total | Gauge | Transmitted data for each network device as reported by /proc/net/dev (bytes). | device | [oasis-node/cmd/common/metrics](https://github.com/oasisprotocol/oasis-core/tree/master/go/oasis-node/cmd/common/metrics/net.go)
oasis_node_net_transmit_packets_total | Gauge | Transmitted data for each network device as reported by /proc/net/dev (packets). | device | [oasis-node/cmd/common/metrics](https://github.com/oasisprotocol/oasis-core/tree/master/go/oasis-node/cmd/common/metrics/net.go)
oasis_p2p_blocked_peers | Gauge | Number of blocked P2P peers. |  | [p2p](https://github.com/oasisprotocol/oasis-core/tree/master/go/p2p/metrics.go)
oasis_p2p_connections | Gauge | Number of P2P connections. |  | [p2p](https://github.com/oasisprotocol/oasis-core/tree/master/go/p2p/metrics.go)
oasis_p2p_peers | Gauge | Number of connected P2P peers. |  | [p2p](https://github.com/oasisprotocol/oasis-core/tree/master/go/p2p/metrics.go)
oasis_p2p_protocols | Gauge | Number of supported P2P protocols. |  | [p2p](https://github.com/oasisprotocol/oasis-core/tree/master/go/p2p/metrics.go)
oasis_p2p_topics | Gauge | Number of supported P2P topics. |  | [p2p](https://github.com/oasisprotocol/oasis-core/tree/master/go/p2p/metrics.go)
oasis_registry_entities | Gauge | Number of registry entities. |  | [registry](https://github.com/oasisprotocol/oasis-core/tree/master/go/registry/metrics.go)
oasis_registry_nodes | Gauge | Number of registry nodes. |  | [registry](https://github.com/oasisprotocol/oasis-core/tree/master/go/registry/metrics.go)
oasis_registry_runtimes | Gauge | Number of registry runtimes. |  | [registry](https://github.com/oasisprotocol/oasis-core/tree/master/go/registry/metrics.go)
oasis_rhp_failures | Counter | Number of failed Runtime Host calls. | call | [runtime/host/protocol](https://github.com/oasisprotocol/oasis-core/tree/master/go/runtime/host/protocol/metrics.go)
oasis_rhp_latency | Summary | Runtime Host call latency (seconds). | call | [runtime/host/protocol](https://github.com/oasisprotocol/oasis-core/tree/master/go/runtime/host/protocol/metrics.go)
oasis_rhp_successes | Counter | Number of successful Runtime Host calls. | call | [runtime/host/protocol](https://github.com/oasisprotocol/oasis-core/tree/master/go/runtime/host/protocol/metrics.go)
oasis_rhp_timeouts | Counter | Number of timed out Runtime Host calls. |  | [runtime/host/protocol](https://github.com/oasisprotocol/oasis-core/tree/master/go/runtime/host/protocol/metrics.go)
oasis_roothash_block_interval | Summary | Time between roothash blocks (seconds). | runtime | [roothash](https://github.com/oasisprotocol/oasis-core/tree/master/go/roothash/metrics.go)
oasis_storage_failures | Counter | Number of storage failures. | call | [storage/api](https://github.com/oasisprotocol/oasis-core/tree/master/go/storage/api/metrics.go)
oasis_storage_latency | Summary | Storage call latency (seconds). | call | [storage/api](https://github.com/oasisprotocol/oasis-core/tree/master/go/storage/api/metrics.go)
oasis_storage_successes | Counter | Number of storage successes. | call | [storage/api](https://github.com/oasisprotocol/oasis-core/tree/master/go/storage/api/metrics.go)
oasis_storage_value_size | Summary | Storage call value size (bytes). | call | [storage/api](https://github.com/oasisprotocol/oasis-core/tree/master/go/storage/api/metrics.go)
oasis_tee_attestations_failed | Counter | Number of failed TEE attestations. | runtime, kind | [runtime/host/sgx/common](https://github.com/oasisprotocol/oasis-core/tree/master/go/runtime/host/sgx/common/metrics.go)
oasis_tee_attestations_performed | Counter | Number of TEE attestations performed. | runtime, kind | [runtime/host/sgx/common](https://github.com/oasisprotocol/oasis-core/tree/master/go/runtime/host/sgx/common/metrics.go)
oasis_tee_attestations_successful | Counter | Number of successful TEE attestations. | runtime, kind | [runtime/host/sgx/common](https://github.com/oasisprotocol/oasis-core/tree/master/go/runtime/host/sgx/common/metrics.go)
oasis_txpool_accepted_transactions | Counter | Number of accepted transactions (passing check tx). | runtime | [runtime/txpool](https://github.com/oasisprotocol/oasis-core/tree/master/go/runtime/txpool/metrics.go)
oasis_txpool_local_queue_size | Gauge | Size of the local transactions schedulable queue (number of entries). | runtime | [runtime/txpool](https://github.com/oasisprotocol/oasis-core/tree/master/go/runtime/txpool/metrics.go)
oasis_txpool_pending_check_size | Gauge | Size of the pending to be checked queue (number of entries). | runtime | [runtime/txpool](https://github.com/oasisprotocol/oasis-core/tree/master/go/runtime/txpool/metrics.go)
oasis_txpool_pending_schedule_size | Gauge | Size of the main schedulable queue (number of entries). | runtime | [runtime/txpool](https://github.com/oasisprotocol/oasis-core/tree/master/go/runtime/txpool/metrics.go)
oasis_txpool_rejected_transactions | Counter | Number of rejected transactions (failing check tx). | runtime | [runtime/txpool](https://github.com/oasisprotocol/oasis-core/tree/master/go/runtime/txpool/metrics.go)
oasis_txpool_rim_queue_size | Gauge | Size of the roothash incoming message transactions schedulable queue (number of entries). | runtime | [runtime/txpool](https://github.com/oasisprotocol/oasis-core/tree/master/go/runtime/txpool/metrics.go)
oasis_up | Gauge | Is oasis-test-runner active for specific scenario. |  | [oasis-node/cmd/common/metrics](https://github.com/oasisprotocol/oasis-core/tree/master/go/oasis-node/cmd/common/metrics/metrics.go)
oasis_worker_aborted_batch_count | Counter | Number of aborted batches. | runtime | [worker/compute/executor/committee](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/compute/executor/committee/metrics.go)
oasis_worker_batch_processing_time | Summary | Time it takes for a batch to finalize (seconds). | runtime | [worker/compute/executor/committee](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/compute/executor/committee/metrics.go)
oasis_worker_batch_runtime_processing_time | Summary | Time it takes for a batch to be processed by the runtime (seconds). | runtime | [worker/compute/executor/committee](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/compute/executor/committee/metrics.go)
oasis_worker_batch_size | Summary | Number of transactions in a batch. | runtime | [worker/compute/executor/committee](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/compute/executor/committee/metrics.go)
oasis_worker_client_lb_healthy_instance_count | Gauge | Number of healthy instances in the load balancer. | runtime | [runtime/host/loadbalance](https://github.com/oasisprotocol/oasis-core/tree/master/go/runtime/host/loadbalance/metrics.go)
oasis_worker_client_lb_requests | Counter | Number of requests processed by the given load balancer instance. | runtime, lb_instance | [runtime/host/loadbalance](https://github.com/oasisprotocol/oasis-core/tree/master/go/runtime/host/loadbalance/metrics.go)
oasis_worker_epoch_number | Gauge | Current epoch number as seen by the worker. | runtime | [worker/common/committee](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/common/committee/node.go)
oasis_worker_epoch_transition_count | Counter | Number of epoch transitions. | runtime | [worker/common/committee](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/common/committee/node.go)
oasis_worker_execution_discrepancy_detected_count | Counter | Number of detected execute discrepancies. | runtime | [worker/compute/executor/committee](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/compute/executor/committee/metrics.go)
oasis_worker_executor_committee_p2p_peers | Gauge | Number of executor committee P2P peers. | runtime | [worker/common/committee](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/common/committee/node.go)
oasis_worker_executor_is_backup_worker | Gauge | 1 if worker is currently an executor backup worker, 0 otherwise. | runtime | [worker/common/committee](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/common/committee/node.go)
oasis_worker_executor_is_worker | Gauge | 1 if worker is currently an executor worker, 0 otherwise. | runtime | [worker/common/committee](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/common/committee/node.go)
oasis_worker_executor_liveness_live_ratio | Gauge | Ratio between live and total rounds. Reports 1 if node is not in committee. | runtime | [worker/common/committee](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/common/committee/node.go)
oasis_worker_executor_liveness_live_rounds | Gauge | Number of live rounds in last epoch. | runtime | [worker/common/committee](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/common/committee/node.go)
oasis_worker_executor_liveness_total_rounds | Gauge | Number of total rounds in last epoch. | runtime | [worker/common/committee](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/common/committee/node.go)
oasis_worker_failed_round_count | Counter | Number of failed roothash rounds. | runtime | [worker/common/committee](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/common/committee/node.go)
oasis_worker_keymanager_churp_committee_size | Gauge | Number of nodes in the committee | runtime, churp | [worker/keymanager](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/keymanager/metrics.go)
oasis_worker_keymanager_churp_confirmed_applications_total | Gauge | Number of confirmed applications | runtime, churp | [worker/keymanager](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/keymanager/metrics.go)
oasis_worker_keymanager_churp_enclave_rpc_failures_total | Counter | Number of failed enclave rpc calls. | runtime, churp, method | [worker/keymanager](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/keymanager/metrics.go)
oasis_worker_keymanager_churp_enclave_rpc_latency_seconds | Summary | Latency of enclave rpc calls in seconds. | runtime, churp, method | [worker/keymanager](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/keymanager/metrics.go)
oasis_worker_keymanager_churp_extra_shares_number | Gauge | Minimum number of extra shares. | runtime, churp | [worker/keymanager](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/keymanager/metrics.go)
oasis_worker_keymanager_churp_handoff_interval | Gauge | Handoff interval in epochs | runtime, churp | [worker/keymanager](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/keymanager/metrics.go)
oasis_worker_keymanager_churp_handoff_number | Counter | Epoch number of the last handoff | runtime, churp | [worker/keymanager](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/keymanager/metrics.go)
oasis_worker_keymanager_churp_next_handoff_number | Counter | Epoch number of the next handoff | runtime, churp | [worker/keymanager](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/keymanager/metrics.go)
oasis_worker_keymanager_churp_submitted_applications_total | Gauge | Number of submitted applications | runtime, churp | [worker/keymanager](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/keymanager/metrics.go)
oasis_worker_keymanager_churp_threshold_number | Counter | Degree of the secret-sharing polynomial | runtime, churp | [worker/keymanager](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/keymanager/metrics.go)
oasis_worker_keymanager_compute_runtime_count | Counter | Number of compute runtimes using the key manager. | runtime | [worker/keymanager](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/keymanager/metrics.go)
oasis_worker_keymanager_consensus_ephemeral_secret_epoch_number | Gauge | Epoch number of the latest ephemeral secret. | runtime | [worker/keymanager](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/keymanager/metrics.go)
oasis_worker_keymanager_consensus_master_secret_generation_number | Gauge | Generation number of the latest master secret. | runtime | [worker/keymanager](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/keymanager/metrics.go)
oasis_worker_keymanager_consensus_master_secret_proposal_epoch_number | Gauge | Epoch number of the latest master secret proposal. | runtime | [worker/keymanager](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/keymanager/metrics.go)
oasis_worker_keymanager_consensus_master_secret_proposal_generation_number | Gauge | Generation number of the latest master secret proposal. | runtime | [worker/keymanager](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/keymanager/metrics.go)
oasis_worker_keymanager_consensus_master_secret_rotation_epoch_number | Gauge | Epoch number of the latest master secret rotation. | runtime | [worker/keymanager](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/keymanager/metrics.go)
oasis_worker_keymanager_enclave_ephemeral_secret_epoch_number | Gauge | Epoch number of the latest ephemeral secret loaded into the enclave. | runtime | [worker/keymanager](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/keymanager/metrics.go)
oasis_worker_keymanager_enclave_generated_ephemeral_secret_epoch_number | Gauge | Epoch number of the latest ephemeral secret generated by the enclave. | runtime | [worker/keymanager](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/keymanager/metrics.go)
oasis_worker_keymanager_enclave_generated_master_secret_epoch_number | Gauge | Epoch number of the latest master secret generated by the enclave. | runtime | [worker/keymanager](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/keymanager/metrics.go)
oasis_worker_keymanager_enclave_generated_master_secret_generation_number | Gauge | Generation number of the latest master secret generated by the enclave. | runtime | [worker/keymanager](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/keymanager/metrics.go)
oasis_worker_keymanager_enclave_master_secret_generation_number | Gauge | Generation number of the latest master secret as seen by the enclave. | runtime | [worker/keymanager](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/keymanager/metrics.go)
oasis_worker_keymanager_enclave_master_secret_proposal_epoch_number | Gauge | Epoch number of the latest master secret proposal loaded into the enclave. | runtime | [worker/keymanager](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/keymanager/metrics.go)
oasis_worker_keymanager_enclave_master_secret_proposal_generation_number | Gauge | Generation number of the latest master secret proposal loaded into the enclave. | runtime | [worker/keymanager](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/keymanager/metrics.go)
oasis_worker_keymanager_enclave_rpc_count | Counter | Number of remote Enclave RPC requests via P2P. | method | [worker/keymanager/p2p](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/keymanager/p2p/metrics.go)
oasis_worker_keymanager_policy_update_count | Counter | Number of key manager policy updates. | runtime | [worker/keymanager](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/keymanager/metrics.go)
oasis_worker_node_registered | Gauge | Is oasis node registered (binary). |  | [worker/registration](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/registration/worker.go)
oasis_worker_node_registration_eligible | Gauge | Is oasis node eligible for registration (binary). |  | [worker/registration](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/registration/worker.go)
oasis_worker_node_status_frozen | Gauge | Is oasis node frozen (binary). |  | [worker/registration](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/registration/worker.go)
oasis_worker_node_status_runtime_faults | Gauge | Number of runtime faults. | runtime | [worker/registration](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/registration/worker.go)
oasis_worker_node_status_runtime_suspended | Gauge | Runtime node suspension status (binary). | runtime | [worker/registration](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/registration/worker.go)
oasis_worker_processed_block_count | Counter | Number of processed roothash blocks. | runtime | [worker/common/committee](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/common/committee/node.go)
oasis_worker_processed_event_count | Counter | Number of processed roothash events. | runtime | [worker/compute/executor/committee](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/compute/executor/committee/metrics.go)
oasis_worker_storage_commit_latency | Summary | Latency of storage commit calls (state + outputs) (seconds). | runtime | [worker/compute/executor/committee](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/compute/executor/committee/metrics.go)
oasis_worker_storage_full_round | Gauge | The last round that was fully synced and finalized. | runtime | [worker/storage/committee](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/storage/committee/metrics.go)
oasis_worker_storage_pending_round | Gauge | The last round that is in-flight for syncing. | runtime | [worker/storage/committee](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/storage/committee/metrics.go)
oasis_worker_storage_round_sync_latency | Summary | Storage round sync latency (seconds). | runtime | [worker/storage/committee](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/storage/committee/metrics.go)
oasis_worker_storage_synced_round | Gauge | The last round that was synced but not yet finalized. | runtime | [worker/storage/committee](https://github.com/oasisprotocol/oasis-core/tree/master/go/worker/storage/committee/metrics.go)

<!-- markdownlint-enable line-length -->

## Consensus backends

### Metrics Reported by *CometBFT*

When `oasis-node` is configured to use [CometBFT][1] for BFT consensus, all
CometBFT metrics are also reported. Consult
[CometBFT-core documentation][2] for a list of reported by CometBFT.

[1]: ../consensus/README.md#cometbft
[2]: https://docs.cometbft.com/v0.38/core/metrics
