use crate::wire::{Decoder, WireError};

#[cfg(test)]
use crate::wire::Encoder;

pub(crate) const MAGIC: u32 = 0x0001_0000;
pub(crate) const BUCKET_STRAW2: u32 = 5;
pub(crate) const HASH_RJENKINS1: u8 = 0;
pub(crate) const RULE_TAKE: u32 = 1;
pub(crate) const RULE_CHOOSE_FIRST_N: u32 = 2;
pub(crate) const RULE_CHOOSE_INDEP: u32 = 3;
pub(crate) const RULE_EMIT: u32 = 4;
pub(crate) const RULE_CHOOSELEAF_FIRST_N: u32 = 6;
pub(crate) const RULE_CHOOSELEAF_INDEP: u32 = 7;
pub(crate) const RULE_SET_CHOOSE_TRIES: u32 = 8;
pub(crate) const RULE_SET_CHOOSELEAF_TRIES: u32 = 9;
pub(crate) const RULE_TYPE_REPLICATED: u8 = 1;
pub(crate) const RULE_TYPE_ERASURE: u8 = 3;

const MAX_CERTIFIED_RETRIES: u32 = 1_000;
pub(crate) const MAX_CERTIFIED_DEPTH: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DecodeError {
    Wire(WireError),
    Unsupported,
}

impl From<WireError> for DecodeError {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GraphError {
    Malformed,
    DepthExceeded,
}

#[allow(clippy::struct_field_names)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DecodeLimits {
    pub(crate) max_bytes: u32,
    pub(crate) max_buckets: u32,
    pub(crate) max_rules: u32,
    pub(crate) max_items: u32,
    pub(crate) max_names: u32,
}

#[allow(clippy::struct_field_names)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Bucket {
    pub(crate) id: i32,
    pub(crate) bucket_type: u16,
    pub(crate) weight: u32,
    pub(crate) items: Vec<i32>,
    pub(crate) item_weights: Vec<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RuleStep {
    pub(crate) operation: u32,
    pub(crate) argument1: i32,
    pub(crate) argument2: i32,
}

#[allow(clippy::struct_field_names)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Rule {
    pub(crate) rule_type: u8,
    pub(crate) min_size: u8,
    pub(crate) max_size: u8,
    pub(crate) steps: Vec<RuleStep>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Map {
    pub(crate) max_devices: i32,
    pub(crate) buckets: std::collections::BTreeMap<i32, Bucket>,
    pub(crate) rules: std::collections::BTreeMap<u32, Rule>,
    pub(crate) choose_local_tries: u32,
    pub(crate) choose_local_fallback_tries: u32,
    pub(crate) choose_total_tries: u32,
    pub(crate) chooseleaf_descend_once: u32,
    pub(crate) chooseleaf_vary_r: u8,
    pub(crate) straw_calc_version: u8,
    pub(crate) allowed_bucket_algorithms: u32,
    pub(crate) chooseleaf_stable: u8,
    pub(crate) msr_descents: u32,
    pub(crate) msr_collision_tries: u32,
    pub(crate) class_shadow_buckets: std::collections::BTreeSet<i32>,
}

impl Map {
    #[allow(clippy::too_many_lines)]
    pub(crate) fn decode(data: &[u8], limits: DecodeLimits) -> Result<Self, DecodeError> {
        if limits.max_bytes == 0
            || limits.max_buckets == 0
            || limits.max_rules == 0
            || limits.max_items == 0
            || limits.max_names == 0
        {
            return Err(WireError::LimitExceeded.into());
        }

        let mut decoder = Decoder::new(data, limits.max_bytes as usize);
        if decoder.u32() != MAGIC {
            return Err(WireError::Malformed.into());
        }
        let max_buckets = decoder.i32();
        let max_rules = decoder.u32();
        let max_devices = decoder.i32();
        decoder.finish()?;

        if max_buckets < 0
            || u32::try_from(max_buckets).unwrap_or(u32::MAX) > limits.max_buckets
            || max_rules > limits.max_rules
            || max_devices < 0
            || u32::try_from(max_devices).unwrap_or(u32::MAX) > limits.max_items
        {
            return Err(WireError::LimitExceeded.into());
        }

        let mut result = Self {
            max_devices,
            buckets: std::collections::BTreeMap::new(),
            rules: std::collections::BTreeMap::new(),
            choose_local_tries: 2,
            choose_local_fallback_tries: 5,
            choose_total_tries: 19,
            chooseleaf_descend_once: 0,
            chooseleaf_vary_r: 0,
            straw_calc_version: 0,
            allowed_bucket_algorithms: (1 << 1) | (1 << 2) | (1 << 4),
            chooseleaf_stable: 0,
            msr_descents: 0,
            msr_collision_tries: 0,
            class_shadow_buckets: std::collections::BTreeSet::new(),
        };

        for index in 0..max_buckets {
            let algorithm = decoder.u32();
            if algorithm == 0 {
                continue;
            }
            if algorithm != BUCKET_STRAW2 {
                return Err(DecodeError::Unsupported);
            }

            let id = decoder.i32();
            let bucket_type = decoder.u16();
            let encoded_algorithm = decoder.u8();
            let hash = decoder.u8();
            let weight = decoder.u32();
            let count = decoder.u32();
            decoder.finish()?;

            if id != -1 - index
                || encoded_algorithm != u8::try_from(BUCKET_STRAW2).expect("algorithm fits")
                || hash != HASH_RJENKINS1
            {
                return Err(WireError::Malformed.into());
            }
            if count > limits.max_items {
                return Err(WireError::LimitExceeded.into());
            }
            if u64::from(count) * 8 > decoder.remaining() as u64 {
                return Err(WireError::Malformed.into());
            }

            let count = usize::try_from(count).map_err(|_| WireError::LimitExceeded)?;
            let mut items = Vec::with_capacity(count);
            let mut item_weights = Vec::with_capacity(count);
            for _ in 0..count {
                items.push(decoder.i32());
            }
            for _ in 0..count {
                item_weights.push(decoder.u32());
            }
            result.buckets.insert(
                id,
                Bucket {
                    id,
                    bucket_type,
                    weight,
                    items,
                    item_weights,
                },
            );
        }

        for index in 0..max_rules {
            if decoder.u32() == 0 {
                continue;
            }
            let count = decoder.u32();
            if count > limits.max_items {
                return Err(WireError::LimitExceeded.into());
            }
            if u64::from(count) * 12 + 4 > decoder.remaining() as u64 {
                return Err(WireError::Malformed.into());
            }

            let rule_id = decoder.u8();
            let rule_type = decoder.u8();
            let min_size = decoder.u8();
            let max_size = decoder.u8();
            if u32::from(rule_id) != index {
                return Err(WireError::Malformed.into());
            }
            let count = usize::try_from(count).map_err(|_| WireError::LimitExceeded)?;
            let mut steps = Vec::with_capacity(count);
            for _ in 0..count {
                steps.push(RuleStep {
                    operation: decoder.u32(),
                    argument1: decoder.i32(),
                    argument2: decoder.i32(),
                });
            }
            result.rules.insert(
                index,
                Rule {
                    rule_type,
                    min_size,
                    max_size,
                    steps,
                },
            );
        }

        for _ in 0..3 {
            consume_name_map(&mut decoder, limits.max_names)?;
        }
        if decoder.remaining() >= 12 {
            result.choose_local_tries = decoder.u32();
            result.choose_local_fallback_tries = decoder.u32();
            result.choose_total_tries = decoder.u32();
            if result.choose_local_tries > MAX_CERTIFIED_RETRIES
                || result.choose_local_fallback_tries > MAX_CERTIFIED_RETRIES
                || result.choose_total_tries >= MAX_CERTIFIED_RETRIES
            {
                return Err(DecodeError::Unsupported);
            }
        }
        if decoder.remaining() >= 4 {
            result.chooseleaf_descend_once = decoder.u32();
        }
        if decoder.remaining() >= 1 {
            result.chooseleaf_vary_r = decoder.u8();
        }
        if decoder.remaining() >= 1 {
            result.straw_calc_version = decoder.u8();
        }
        if decoder.remaining() >= 4 {
            result.allowed_bucket_algorithms = decoder.u32();
        }
        if decoder.remaining() >= 1 {
            result.chooseleaf_stable = decoder.u8();
        }
        if decoder.remaining() != 0 {
            consume_int_map(&mut decoder, limits.max_names)?;
            consume_name_map(&mut decoder, limits.max_names)?;
            result.class_shadow_buckets = consume_nested_int_map(&mut decoder, limits.max_names)?;
            if decoder.u32() != 0 {
                return Err(DecodeError::Unsupported);
            }
        }
        if decoder.remaining() >= 8 {
            result.msr_descents = decoder.u32();
            result.msr_collision_tries = decoder.u32();
        }
        if decoder.remaining() != 0 {
            return Err(WireError::Malformed.into());
        }
        decoder.finish()?;
        result
            .validate_graph()
            .map_err(Self::map_graph_decode_error)?;
        Ok(result)
    }

    pub(crate) fn has_bucket_type(&self, bucket_type: u16) -> bool {
        self.buckets
            .values()
            .any(|bucket| bucket.bucket_type == bucket_type)
    }

    pub(crate) fn validate_graph(&self) -> Result<(), GraphError> {
        let mut states = std::collections::BTreeMap::new();
        let mut heights = std::collections::BTreeMap::new();

        for id in self.buckets.keys().copied() {
            self.visit_bucket(id, 1, &mut states, &mut heights)?;
        }
        Ok(())
    }

    fn visit_bucket(
        &self,
        id: i32,
        depth: usize,
        states: &mut std::collections::BTreeMap<i32, u8>,
        heights: &mut std::collections::BTreeMap<i32, usize>,
    ) -> Result<usize, GraphError> {
        if depth > MAX_CERTIFIED_DEPTH {
            return Err(GraphError::DepthExceeded);
        }
        match states.get(&id).copied() {
            Some(1) => return Err(GraphError::Malformed),
            Some(2) => {
                let height = heights[&id];
                if depth + height - 1 > MAX_CERTIFIED_DEPTH {
                    return Err(GraphError::DepthExceeded);
                }
                return Ok(height);
            }
            _ => {}
        }

        let bucket = self.buckets.get(&id).ok_or(GraphError::Malformed)?;
        states.insert(id, 1);
        let mut height = 1_usize;
        for item in &bucket.items {
            if *item >= 0 {
                if *item >= self.max_devices {
                    return Err(GraphError::Malformed);
                }
                continue;
            }
            if !self.buckets.contains_key(item) {
                return Err(GraphError::Malformed);
            }
            let child_height = self.visit_bucket(*item, depth + 1, states, heights)?;
            height = height.max(child_height + 1);
        }
        states.insert(id, 2);
        heights.insert(id, height);
        Ok(height)
    }

    fn map_graph_decode_error(error: GraphError) -> DecodeError {
        match error {
            GraphError::Malformed => WireError::Malformed.into(),
            GraphError::DepthExceeded => DecodeError::Unsupported,
        }
    }
}

fn bounded_count(
    decoder: &mut Decoder<'_>,
    maximum: u32,
    minimum_bytes: usize,
) -> Result<usize, WireError> {
    let count = decoder.u32();
    decoder.finish()?;
    if count > maximum {
        return Err(WireError::LimitExceeded);
    }
    let count = usize::try_from(count).map_err(|_| WireError::LimitExceeded)?;
    if minimum_bytes != 0 && count > decoder.remaining() / minimum_bytes {
        return Err(WireError::Malformed);
    }
    Ok(count)
}

fn consume_name_map(decoder: &mut Decoder<'_>, maximum: u32) -> Result<(), WireError> {
    let count = bounded_count(decoder, maximum, 4)?;
    for _ in 0..count {
        decoder.i32();
        let _ = decoder.string();
    }
    decoder.finish()
}

fn consume_int_map(decoder: &mut Decoder<'_>, maximum: u32) -> Result<(), WireError> {
    let count = bounded_count(decoder, maximum, 8)?;
    for _ in 0..count {
        decoder.i32();
        decoder.i32();
    }
    decoder.finish()
}

fn consume_nested_int_map(
    decoder: &mut Decoder<'_>,
    maximum: u32,
) -> Result<std::collections::BTreeSet<i32>, WireError> {
    let count = bounded_count(decoder, maximum, 8)?;
    let mut values = std::collections::BTreeSet::new();
    for _ in 0..count {
        decoder.i32();
        let inner = bounded_count(decoder, maximum, 8)?;
        for _ in 0..inner {
            decoder.i32();
            values.insert(decoder.i32());
        }
    }
    decoder.finish()?;
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_decode_limits() -> DecodeLimits {
        DecodeLimits {
            max_bytes: 4_096,
            max_buckets: 16,
            max_rules: 16,
            max_items: 64,
            max_names: 64,
        }
    }

    fn encode_test_map(algorithm: u32, choose_operation: u32) -> Vec<u8> {
        let limits = test_decode_limits();
        let mut encoder = Encoder::new(limits.max_bytes as usize);
        encoder.u32(MAGIC);
        encoder.i32(1);
        encoder.u32(1);
        encoder.i32(3);
        encoder.u32(algorithm);
        if algorithm != 0 {
            encoder.i32(-1);
            encoder.u16(1);
            encoder.u8(u8::try_from(algorithm).expect("test algorithm fits"));
            encoder.u8(HASH_RJENKINS1);
            encoder.u32(3 * 0x1_0000);
            encoder.u32(3);
            for item in 0..3 {
                encoder.i32(item);
            }
            for _ in 0..3 {
                encoder.u32(0x1_0000);
            }
        }
        encoder.u32(1);
        encoder.u32(3);
        encoder.u8(0);
        encoder.u8(RULE_TYPE_REPLICATED);
        encoder.u8(1);
        encoder.u8(10);
        encoder.u32(RULE_TAKE);
        encoder.i32(-1);
        encoder.i32(0);
        encoder.u32(choose_operation);
        encoder.i32(0);
        encoder.i32(0);
        encoder.u32(RULE_EMIT);
        encoder.i32(0);
        encoder.i32(0);
        for _ in 0..3 {
            encoder.u32(0);
        }
        encoder.u32(0);
        encoder.u32(0);
        encoder.u32(50);
        encoder.u32(1);
        encoder.u8(1);
        encoder.u8(1);
        encoder.u32(54);
        encoder.u8(1);
        for _ in 0..4 {
            encoder.u32(0);
        }
        encoder.u32(100);
        encoder.u32(100);
        encoder.finish().expect("encode test map")
    }

    #[test]
    fn decodes_straw2_map() {
        let decoded = Map::decode(
            &encode_test_map(BUCKET_STRAW2, RULE_CHOOSELEAF_FIRST_N),
            test_decode_limits(),
        )
        .expect("decode straw2 map");
        let bucket = &decoded.buckets[&-1];
        let rule = &decoded.rules[&0];
        assert_eq!(decoded.max_devices, 3);
        assert_eq!(bucket.bucket_type, 1);
        assert_eq!(bucket.items.len(), 3);
        assert_eq!(bucket.items[2], 2);
        assert_eq!(bucket.item_weights[0], 0x1_0000);
        assert_eq!(rule.steps.len(), 3);
        assert_eq!(rule.steps[1].operation, RULE_CHOOSELEAF_FIRST_N);
        assert_eq!(decoded.choose_total_tries, 50);
        assert_eq!(decoded.chooseleaf_stable, 1);
    }

    #[test]
    fn decode_rejects_unsupported_features_and_bounds() {
        for (data, expected) in [
            (
                encode_test_map(4, RULE_CHOOSELEAF_FIRST_N),
                DecodeError::Unsupported,
            ),
            (
                encode_test_map(BUCKET_STRAW2, RULE_CHOOSELEAF_FIRST_N)[..20].to_vec(),
                DecodeError::Wire(WireError::Malformed),
            ),
        ] {
            assert_eq!(Map::decode(&data, test_decode_limits()), Err(expected));
        }
    }
}
