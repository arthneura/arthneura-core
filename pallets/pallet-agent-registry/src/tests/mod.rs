//! Unit tests for pallet-agent-registry.

use crate::mock::*;
use crate::pallet::{
    AgentStatus, CapabilityBitmap, Did, Error, Event, QuantumScheme, CAP_DATA_PROVIDER,
    CAP_INFERENCE_ENGINE, MAX_LABEL_LEN, MAX_METADATA_LEN,
};
use frame_support::{assert_noop, assert_ok, BoundedVec};
use sp_runtime::DispatchError;

fn metadata() -> BoundedVec<u8, frame_support::traits::ConstU32<MAX_METADATA_LEN>> {
    BoundedVec::default()
}

fn label() -> BoundedVec<u8, frame_support::traits::ConstU32<MAX_LABEL_LEN>> {
    BoundedVec::default()
}

mod give_star;
mod register_agent;
mod remove_star;
mod set_agent_status;
mod update_profile;
mod deregister_agent;
mod slash_reputation;
