#![forbid(unsafe_code)]

mod hash;
mod ln;
mod map;
mod place;

#[allow(unused_imports)]
pub(crate) use hash::{hash32_pair, hash32_triple, object_hash, stable_mod};
#[allow(unused_imports)]
pub(crate) use ln::crush_ln;
#[allow(unused_imports)]
pub(crate) use map::{
    BUCKET_STRAW2, DecodeError, DecodeLimits, GraphError, HASH_RJENKINS1, MAGIC, Map,
    RULE_CHOOSE_FIRST_N, RULE_CHOOSE_INDEP, RULE_CHOOSELEAF_FIRST_N, RULE_CHOOSELEAF_INDEP,
    RULE_EMIT, RULE_SET_CHOOSE_TRIES, RULE_SET_CHOOSELEAF_TRIES, RULE_TAKE, RULE_TYPE_ERASURE,
    RULE_TYPE_REPLICATED, Rule, RuleStep,
};
#[allow(unused_imports)]
pub(crate) use place::PlacementError;
