//! Test suite for `pallet-vector-db`.
//!
//! One submodule per extrinsic. Every submodule does `use super::*` to inherit
//! the common imports defined here, keeping individual test files minimal.

use crate::mock::{
    derive_commitment_id, metadata, new_test_ext, register_test_agent, test_did,
    test_vector_hash, Runtime, RuntimeOrigin, System, VectorDb,
};
use crate::pallet::{CommitmentStatus, DisputeVerdict, Error, Event};
use frame_support::{assert_noop, assert_ok};
use sp_runtime::DispatchError;

mod acknowledge_commitment;
mod close_commitment;
mod counter_dispute;
mod expire_commitment;
mod finalize_dispute;
mod raise_dispute;
mod register_commitment;
