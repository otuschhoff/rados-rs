#![forbid(unsafe_code)]

pub(crate) mod backoff;
mod client;
pub(crate) mod enumeration;
pub(crate) mod lock;
pub(crate) mod messages;
pub(crate) mod metadata;
pub(crate) mod watch;

pub(crate) use backoff::{HObject, compare_hobject};
#[cfg(feature = "r08-integration")]
pub(crate) use client::fuzz_mutation_lifecycle;
pub(crate) use client::{
    Client, CompoundResult, Error as ClientError, Mutation as OSDMutation, Target, UnknownCause,
};
pub(crate) use messages::NO_SNAP;
pub(crate) use messages::Operation;
