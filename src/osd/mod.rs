#![forbid(unsafe_code)]

pub(crate) mod backoff;
mod client;
pub(crate) mod messages;

pub(crate) use client::{Client, Error as ClientError, Target};
pub(crate) use messages::NO_SNAP;
