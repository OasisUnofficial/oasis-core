use oasis_core_runtime::{
    common::{
        crypto::signature::{self, Signature},
        namespace::Namespace,
    },
    consensus::{beacon::EpochTime, keymanager::SignedEncryptedEphemeralSecret},
};

use crate::crypto::{KeyPairId, Secret};

/// Key manager initialization request.
#[derive(Clone, Default, cbor::Encode, cbor::Decode)]
pub struct InitRequest {
    /// Checksum for validating replication.
    pub checksum: Vec<u8>,
    /// Policy for queries/replication.
    pub policy: Vec<u8>,
    /// True iff the enclave may generate a new master secret.
    pub may_generate: bool,
}

/// Key manager initialization response.
#[derive(Clone, Default, Debug, cbor::Encode, cbor::Decode)]
pub struct InitResponse {
    /// True iff the key manager thinks it's running in a secure mode.
    pub is_secure: bool,
    /// Checksum for validating replication.
    pub checksum: Vec<u8>,
    /// Checksum for identifying policy.
    pub policy_checksum: Vec<u8>,
    /// Runtime signing key.
    pub rsk: signature::PublicKey,
}

/// Signed InitResponse.
#[derive(Clone, Default, cbor::Encode, cbor::Decode)]
pub struct SignedInitResponse {
    /// InitResponse.
    pub init_response: InitResponse,
    /// Sign(init_response).
    pub signature: Signature,
}

/// Key manager master secret replication request.
#[derive(Clone, Default, cbor::Encode, cbor::Decode)]
pub struct ReplicateMasterSecretRequest {
    /// Latest trust root height.
    pub height: Option<u64>,
}

/// Key manager master secret replication response.
#[derive(Clone, Default, cbor::Encode, cbor::Decode)]
pub struct ReplicateMasterSecretResponse {
    /// Master secret.
    pub master_secret: Secret,
}

/// Key manager ephemeral secret replication request.
#[derive(Clone, Default, cbor::Encode, cbor::Decode)]
pub struct ReplicateEphemeralSecretRequest {
    /// Latest trust root height.
    pub height: Option<u64>,
    /// Epoch time.
    pub epoch: EpochTime,
}

/// Key manager ephemeral secret replication response.
#[derive(Clone, Default, cbor::Encode, cbor::Decode)]
pub struct ReplicateEphemeralSecretResponse {
    /// Ephemeral secret.
    pub ephemeral_secret: Secret,
}

/// Generate ephemeral secret request.
#[derive(Clone, Default, cbor::Encode, cbor::Decode)]
pub struct GenerateEphemeralSecretRequest {
    /// Epoch time.
    pub epoch: EpochTime,
}

/// Generate ephemeral secret response.
#[derive(Clone, Default, cbor::Encode, cbor::Decode)]
pub struct GenerateEphemeralSecretResponse {
    /// Signed encrypted ephemeral secret.
    pub signed_secret: SignedEncryptedEphemeralSecret,
}

/// Load ephemeral secret request.
#[derive(Clone, Default, cbor::Encode, cbor::Decode)]
pub struct LoadEphemeralSecretRequest {
    /// Signed encrypted ephemeral secret.
    pub signed_secret: SignedEncryptedEphemeralSecret,
}

/// Long-term key request for private/public key generation and retrieval.
///
/// Long-term keys are runtime-scoped long-lived keys derived by the key manager
/// from the master secret. They can be generated at any time.
#[derive(Clone, Default, cbor::Encode, cbor::Decode)]
pub struct LongTermKeyRequest {
    /// Latest trust root height.
    pub height: Option<u64>,
    /// Runtime ID.
    pub runtime_id: Namespace,
    /// Key pair ID.
    pub key_pair_id: KeyPairId,
}

impl LongTermKeyRequest {
    pub fn new(height: Option<u64>, runtime_id: Namespace, key_pair_id: KeyPairId) -> Self {
        Self {
            height,
            runtime_id,
            key_pair_id,
        }
    }
}

/// Ephemeral key request for private/public key generation and retrieval.
///
/// Ephemeral keys are runtime-scoped short-lived keys derived by
/// the key manager from the master secret. They can only be generated
/// for the past few epochs relative to the consensus layer state.
#[derive(Clone, Default, cbor::Encode, cbor::Decode)]
pub struct EphemeralKeyRequest {
    /// Latest trust root height.
    pub height: Option<u64>,
    /// Runtime ID.
    pub runtime_id: Namespace,
    /// Key pair ID.
    pub key_pair_id: KeyPairId,
    /// Epoch time.
    pub epoch: EpochTime,
}

impl EphemeralKeyRequest {
    pub fn new(
        height: Option<u64>,
        runtime_id: Namespace,
        key_pair_id: KeyPairId,
        epoch: EpochTime,
    ) -> Self {
        Self {
            height,
            runtime_id,
            key_pair_id,
            epoch,
        }
    }
}
