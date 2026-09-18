#![forbid(unsafe_code)]

pub(crate) mod backoff;
mod client;
pub(crate) mod messages;

#[cfg(feature = "r08-integration")]
pub(crate) use client::fuzz_mutation_lifecycle;
pub(crate) use client::{
    Client, Error as ClientError, Mutation as OSDMutation, Target, UnknownCause,
};
pub(crate) use messages::NO_SNAP;
