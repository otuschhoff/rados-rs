#![forbid(unsafe_code)]

pub(crate) mod backoff;
mod client;
pub(crate) mod command;
pub(crate) mod enumeration;
pub(crate) mod inconsistent;
pub(crate) mod lock;
pub(crate) mod messages;
pub(crate) mod metadata;
pub(crate) mod special;
pub(crate) mod watch;

pub(crate) use backoff::{HObject, compare_hobject};
#[cfg(feature = "r08-integration")]
pub(crate) use client::fuzz_mutation_lifecycle;
pub(crate) use client::{
    Client, CommandResult, CompoundResult, Error as ClientError, Mutation as OSDMutation, Target,
    UnknownCause,
};
pub(crate) use command::parse_pg;
pub(crate) use messages::NO_SNAP;
pub(crate) use messages::Operation;
