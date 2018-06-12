use std::convert::{Into, TryFrom};
use std::sync::Arc;

use ekiden_common::bytes::B256;
use ekiden_common::error::Result;
use ekiden_common::futures::{future, Future, Stream};
use ekiden_consensus_api as api;
use grpcio::RpcStatusCode::{Internal, InvalidArgument};
use grpcio::{RpcContext, ServerStreamingSink, UnarySink, WriteFlags};

use super::backend::{ConsensusBackend, Event};
use commitment::{Commitment, Reveal};
use header::Header;

#[derive(Clone)]
pub struct ConsensusService {
    inner: Arc<ConsensusBackend>,
}

impl ConsensusService {
    pub fn new(backend: Arc<ConsensusBackend>) -> Self {
        Self { inner: backend }
    }
}

impl api::Consensus for ConsensusService {
    fn get_latest_block(
        &self,
        ctx: RpcContext,
        req: api::LatestBlockRequest,
        sink: UnarySink<api::LatestBlockResponse>,
    ) {
        let f = move || -> Result<_> {
            Ok(self.inner
                .get_latest_block(B256::try_from(req.get_contract_id())?))
        };
        let f = match f() {
            Ok(f) => f.then(|response| match response {
                Ok(block) => {
                    let mut pb_response = api::LatestBlockResponse::new();
                    pb_response.set_block(block.into());

                    Ok(pb_response)
                }
                Err(error) => Err(error),
            }),
            Err(error) => {
                ctx.spawn(invalid_rpc!(sink, InvalidArgument, error).map_err(|_error| ()));
                return;
            }
        };
        ctx.spawn(f.then(move |response| match response {
            Ok(response) => sink.success(response),
            Err(error) => invalid_rpc!(sink, Internal, error),
        }).map_err(|_error| ()));
    }

    fn get_blocks(
        &self,
        ctx: RpcContext,
        req: api::BlockRequest,
        sink: ServerStreamingSink<api::BlockResponse>,
    ) {
        let f = move || -> Result<_> {
            Ok(self.inner
                .get_blocks(B256::try_from(req.get_contract_id())?))
        };
        let f = match f() {
            Ok(f) => f.map(|response| -> (api::BlockResponse, WriteFlags) {
                let mut pb_response = api::BlockResponse::new();
                pb_response.set_block(response.into());

                (pb_response, WriteFlags::default())
            }),
            Err(error) => {
                ctx.spawn(invalid_rpc!(sink, InvalidArgument, error).map_err(|_error| ()));
                return;
            }
        };
        ctx.spawn(f.forward(sink).then(|_f| future::ok(())));
    }

    fn get_events(
        &self,
        ctx: RpcContext,
        req: api::EventRequest,
        sink: ServerStreamingSink<api::EventResponse>,
    ) {
        let f = move || -> Result<_> {
            Ok(self.inner
                .get_events(B256::try_from(req.get_contract_id())?))
        };
        let f = match f() {
            Ok(f) => f.map(|response| -> (api::EventResponse, WriteFlags) {
                let mut event = api::Event::new();
                match response {
                    Event::CommitmentsReceived(discrepancy) => {
                        let mut args = api::Event_CommitmentsReceived::new();
                        args.set_discrepancy(discrepancy);
                        event.set_commitments_received(args);
                    }
                    Event::RoundFailed(error) => {
                        let mut args = api::Event_RoundFailed::new();
                        args.set_error(error.message.to_owned());
                        event.set_round_failed(args);
                    }
                    Event::DiscrepancyDetected(batch_hash) => {
                        let mut args = api::Event_DiscrepancyDetected::new();
                        args.set_batch_hash(batch_hash.to_vec());
                        event.set_discrepancy_detected(args);
                    }
                };

                let mut pb_response = api::EventResponse::new();
                pb_response.set_event(event);

                (pb_response, WriteFlags::default())
            }),
            Err(error) => {
                ctx.spawn(invalid_rpc!(sink, InvalidArgument, error).map_err(|_error| ()));
                return;
            }
        };
        ctx.spawn(f.forward(sink).then(|_f| future::ok(())));
    }

    fn commit(
        &self,
        ctx: RpcContext,
        req: api::CommitRequest,
        sink: UnarySink<api::CommitResponse>,
    ) {
        let f = move || -> Result<_> {
            let contract_id = B256::try_from(req.get_contract_id())?;
            let commitment = Commitment::try_from(req.get_commitment().clone())?;
            Ok(self.inner.commit(contract_id, commitment))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(()) => Ok(api::CommitResponse::new()),
                Err(e) => Err(e),
            }),
            Err(error) => {
                ctx.spawn(invalid_rpc!(sink, InvalidArgument, error).map_err(|_error| ()));
                return;
            }
        };
        ctx.spawn(f.then(move |response| match response {
            Ok(response) => sink.success(response),
            Err(error) => invalid_rpc!(sink, Internal, error),
        }).map_err(|_error| ()));
    }

    fn reveal(
        &self,
        ctx: RpcContext,
        req: api::RevealRequest,
        sink: UnarySink<api::RevealResponse>,
    ) {
        let f = move || -> Result<_> {
            let contract_id = B256::try_from(req.get_contract_id())?;
            let reveal = Reveal::try_from(req.get_reveal().clone())?;

            Ok(self.inner.reveal(contract_id, reveal))
        };
        let f = match f() {
            Ok(f) => f.then(|response| match response {
                Ok(()) => Ok(api::RevealResponse::new()),
                Err(e) => Err(e),
            }),
            Err(error) => {
                ctx.spawn(invalid_rpc!(sink, InvalidArgument, error).map_err(|_error| ()));
                return;
            }
        };
        ctx.spawn(f.then(move |response| match response {
            Ok(response) => sink.success(response),
            Err(error) => invalid_rpc!(sink, Internal, error),
        }).map_err(|_error| ()));
    }

    fn commit_many(
        &self,
        ctx: RpcContext,
        req: api::CommitManyRequest,
        sink: UnarySink<api::CommitResponse>,
    ) {
        let f = move || -> Result<_> {
            let contract_id = B256::try_from(req.get_contract_id())?;
            let mut commitments: Vec<Commitment> = Vec::new();

            for c in req.get_commitments() {
                let commitment = Commitment::try_from(c.clone())?;

                commitments.push(commitment);
            }

            Ok(self.inner.commit_many(contract_id, commitments))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(()) => Ok(api::CommitResponse::new()),
                Err(e) => Err(e),
            }),
            Err(error) => {
                ctx.spawn(invalid_rpc!(sink, InvalidArgument, error).map_err(|_error| ()));
                return;
            }
        };
        ctx.spawn(f.then(move |response| match response {
            Ok(response) => sink.success(response),
            Err(error) => invalid_rpc!(sink, Internal, error),
        }).map_err(|_error| ()));
    }

    fn reveal_many(
        &self,
        ctx: RpcContext,
        req: api::RevealManyRequest,
        sink: UnarySink<api::RevealResponse>,
    ) {
        let f = move || -> Result<_> {
            let contract_id = B256::try_from(req.get_contract_id())?;
            let mut reveals: Vec<Reveal<Header>> = Vec::new();

            for r in req.get_reveals() {
                let reveal = Reveal::try_from(r.clone())?;

                reveals.push(reveal);
            }

            Ok(self.inner.reveal_many(contract_id, reveals))
        };
        let f = match f() {
            Ok(f) => f.then(|response| match response {
                Ok(()) => Ok(api::RevealResponse::new()),
                Err(e) => Err(e),
            }),
            Err(error) => {
                ctx.spawn(invalid_rpc!(sink, InvalidArgument, error).map_err(|_error| ()));
                return;
            }
        };
        ctx.spawn(f.then(move |response| match response {
            Ok(response) => sink.success(response),
            Err(error) => invalid_rpc!(sink, Internal, error),
        }).map_err(|_error| ()));
    }
}
