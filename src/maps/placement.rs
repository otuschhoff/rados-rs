use std::collections::HashSet;

use crate::crush::{self, DecodeError, DecodeLimits, PlacementError};

use super::{MapError, OSDMap, PG, Result};

const OBJECT_HASH_RJENKINS: u8 = 2;
const POOL_TYPE_REPLICATED: u8 = 1;
const POOL_TYPE_ERASURE: u8 = 3;
const POOL_FLAG_HASHPSPOOL: u64 = 1 << 0;
const DEFAULT_PRIMARY_AFFINITY: u32 = 0x1_0000;
const CRUSH_ITEM_NONE: i32 = i32::MAX;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ObjectPlacement {
    pub(crate) raw_hash: u32,
    pub(crate) raw_pg: PG,
    pub(crate) pg: PG,
    pub(crate) placement_seed: u32,
    pub(crate) raw: Vec<i32>,
    pub(crate) up: Vec<i32>,
    pub(crate) up_primary: i32,
    pub(crate) acting: Vec<i32>,
    pub(crate) acting_primary: i32,
    pub(crate) primary_shard: i8,
    pub(crate) sharded: bool,
}

impl OSDMap {
    pub(crate) fn map_object(
        &self,
        pool_id: i64,
        object: &[u8],
        locator: &[u8],
        namespace: &[u8],
    ) -> Result<ObjectPlacement> {
        self.map_raw_hash(pool_id, crush::object_hash(object, locator, namespace))
    }

    pub(crate) fn map_raw_hash(&self, pool_id: i64, hash: u32) -> Result<ObjectPlacement> {
        if pool_id < 0 {
            return Err(MapError::UnsupportedPlacement("negative pool id"));
        }
        let pool = self
            .pools
            .get(&pool_id)
            .ok_or(MapError::UnsupportedPlacement("pool does not exist"))?;
        if pool.object_hash != OBJECT_HASH_RJENKINS {
            return Err(MapError::UnsupportedPlacement("unsupported object hash"));
        }
        if pool.flags & POOL_FLAG_HASHPSPOOL == 0 {
            return Err(MapError::UnsupportedPlacement(
                "pool does not use HASHPSPOOL",
            ));
        }
        if pool.pg_count == 0
            || pool.placement_pg_count == 0
            || pool.placement_pg_count > pool.pg_count
        {
            return Err(MapError::UnsupportedPlacement("invalid PG geometry"));
        }

        let raw_pg = PG {
            pool: u64::try_from(pool_id)
                .map_err(|_| MapError::UnsupportedPlacement("negative pool id"))?,
            seed: hash,
            preferred: -1,
        };
        let mut pg = raw_pg;
        pg.seed = crush::stable_mod(hash, pool.pg_count);
        let placement_pg = crush::stable_mod(hash, pool.placement_pg_count);
        let pool_seed = u32::try_from(pool_id.cast_unsigned() & u64::from(u32::MAX))
            .expect("masked pool id fits u32");

        Ok(ObjectPlacement {
            raw_hash: hash,
            raw_pg,
            pg,
            placement_seed: crush::hash32_pair(placement_pg, pool_seed),
            raw: Vec::new(),
            up: Vec::new(),
            up_primary: -1,
            acting: Vec::new(),
            acting_primary: -1,
            primary_shard: 0,
            sharded: false,
        })
    }

    pub(crate) fn place_object(
        &self,
        pool_id: i64,
        object: &[u8],
        locator: &[u8],
        namespace: &[u8],
    ) -> Result<ObjectPlacement> {
        let placement = self.map_object(pool_id, object, locator, namespace)?;
        self.place_mapped(pool_id, placement)
    }

    pub(crate) fn place_raw_hash(&self, pool_id: i64, hash: u32) -> Result<ObjectPlacement> {
        let placement = self.map_raw_hash(pool_id, hash)?;
        self.place_mapped(pool_id, placement)
    }

    fn place_mapped(
        &self,
        pool_id: i64,
        mut placement: ObjectPlacement,
    ) -> Result<ObjectPlacement> {
        let pool = self
            .pools
            .get(&pool_id)
            .ok_or(MapError::UnsupportedPlacement("pool does not exist"))?;
        if pool.pool_type != POOL_TYPE_REPLICATED && pool.pool_type != POOL_TYPE_ERASURE {
            return Err(MapError::UnsupportedPlacement("unsupported pool type"));
        }
        if pool.size == 0 {
            return Err(MapError::UnsupportedPlacement("pool has zero replicas"));
        }

        let crush_map = self.decode_crush_map()?;
        let raw = crush_map
            .place(
                u32::from(pool.crush_rule),
                placement.placement_seed,
                usize::from(pool.size),
                &self.osd_weight,
            )
            .map_err(|PlacementError| MapError::UnsupportedPlacement("invalid CRUSH placement"))?;

        placement.raw.clone_from(&raw);
        self.validate_upmap(placement.pg)?;

        let sharded = pool.pool_type == POOL_TYPE_ERASURE;
        let mapped = self.apply_upmap(placement.pg, &raw);
        let mut up = self.only_up(&mapped, sharded);
        let mut up_primary = first_osd(&up);
        self.apply_primary_affinity(placement.placement_seed, &mut up, &mut up_primary, !sharded);

        let (mut acting, mut acting_primary) = self.temp_mapping(placement.pg, sharded)?;
        if acting.is_empty() {
            acting.clone_from(&up);
            if acting_primary == -1 {
                acting_primary = up_primary;
            }
        }
        if acting_primary != -1 && !contains_osd(&acting, acting_primary) {
            return Err(MapError::UnsupportedPlacement(
                "temporary primary is not in the acting set",
            ));
        }

        placement.up = up;
        placement.up_primary = up_primary;
        placement.acting = acting;
        placement.acting_primary = acting_primary;

        if pool.pool_type == POOL_TYPE_ERASURE {
            for (index, osd) in placement.acting.iter().copied().enumerate() {
                if osd == placement.acting_primary {
                    if index > 127 {
                        return Err(MapError::UnsupportedPlacement(
                            "erasure primary shard exceeds wire range",
                        ));
                    }
                    placement.primary_shard =
                        i8::try_from(index).expect("wire range checked above");
                    placement.sharded = true;
                    break;
                }
            }
        }

        Ok(placement)
    }

    fn decode_crush_map(&self) -> Result<crate::crush::Map> {
        let max_bytes = u32::try_from(self.crush_data.len())
            .map_err(|_| MapError::UnsupportedPlacement("CRUSH map exceeds supported size"))?;
        let structural_limit = u32::try_from((self.crush_data.len() / 4).max(1))
            .map_err(|_| MapError::UnsupportedPlacement("CRUSH map exceeds supported size"))?;
        crate::crush::Map::decode(
            &self.crush_data,
            DecodeLimits {
                max_bytes,
                max_buckets: structural_limit,
                max_rules: structural_limit,
                max_items: structural_limit,
                max_names: structural_limit,
            },
        )
        .map_err(|error| match error {
            DecodeError::Wire(_) => MapError::UnsupportedPlacement("invalid CRUSH map"),
            DecodeError::Unsupported => MapError::UnsupportedPlacement("unsupported CRUSH map"),
        })
    }

    fn apply_upmap(&self, pg: PG, source: &[i32]) -> Vec<i32> {
        let mut result = source.to_vec();
        if let Some(replacement) = self.pg_upmap.get(&pg) {
            let valid = replacement.iter().copied().all(|osd| {
                osd == CRUSH_ITEM_NONE
                    || osd < 0
                    || usize::try_from(osd)
                        .ok()
                        .and_then(|index| self.osd_weight.get(index))
                        .is_none_or(|&weight| weight != 0)
            });
            if valid {
                result.clone_from(replacement);
            } else {
                return result;
            }
        }

        if let Some(remaps) = self.pg_upmap_items.get(&pg) {
            for remap in remaps {
                let mut target_exists = false;
                let mut position = None;
                let target_out = remap.to != CRUSH_ITEM_NONE
                    && remap.to >= 0
                    && usize::try_from(remap.to)
                        .ok()
                        .and_then(|index| self.osd_weight.get(index))
                        .is_some_and(|&weight| weight == 0);
                for (index, &osd) in result.iter().enumerate() {
                    if osd == remap.to {
                        target_exists = true;
                        break;
                    }
                    if osd == remap.from && position.is_none() && !target_out {
                        position = Some(index);
                    }
                }
                if !target_exists && let Some(index) = position {
                    result[index] = remap.to;
                }
            }
        }

        if let Some(&primary) = self.pg_upmap_primaries.get(&pg) {
            let valid = primary != CRUSH_ITEM_NONE
                && primary >= 0
                && usize::try_from(primary)
                    .ok()
                    .and_then(|index| self.osd_weight.get(index))
                    .is_some_and(|&weight| weight != 0);
            if valid {
                for index in 1..result.len() {
                    if result[index] == primary {
                        result.swap(0, index);
                        break;
                    }
                }
            }
        }

        result
    }

    fn validate_upmap(&self, pg: PG) -> Result<()> {
        if let Some(replacement) = self.pg_upmap.get(&pg) {
            self.validate_placement_set("pg_upmap", replacement, false)?;
        }
        if let Some(remaps) = self.pg_upmap_items.get(&pg) {
            for remap in remaps {
                if remap.to != CRUSH_ITEM_NONE && !self.exists(remap.to) {
                    return Err(MapError::UnsupportedPlacement(
                        "pg_upmap_items references nonexistent OSD",
                    ));
                }
            }
        }
        Ok(())
    }

    fn only_up(&self, source: &[i32], preserve_slots: bool) -> Vec<i32> {
        source
            .iter()
            .filter_map(|&osd| {
                if self.is_up(osd) {
                    Some(osd)
                } else if preserve_slots {
                    Some(CRUSH_ITEM_NONE)
                } else {
                    None
                }
            })
            .collect()
    }

    fn temp_mapping(&self, pg: PG, preserve_slots: bool) -> Result<(Vec<i32>, i32)> {
        let mut primary = self.primary_temp.get(&pg).copied().unwrap_or(-1);
        let Some(source) = self.pg_temp.get(&pg) else {
            return Ok((Vec::new(), primary));
        };
        self.validate_placement_set("pg_temp", source, preserve_slots)?;
        let result = self.only_up(source, preserve_slots);
        if primary == -1 {
            primary = first_osd(&result);
        }
        Ok((result, primary))
    }

    fn apply_primary_affinity(
        &self,
        seed: u32,
        osds: &mut [i32],
        primary: &mut i32,
        shift_primary: bool,
    ) {
        if self.primary_affinity.is_empty() {
            return;
        }
        let mut position = None;
        for (index, &osd) in osds.iter().enumerate() {
            if osd == CRUSH_ITEM_NONE || osd < 0 {
                continue;
            }
            let Some(&affinity) = usize::try_from(osd)
                .ok()
                .and_then(|osd_index| self.primary_affinity.get(osd_index))
            else {
                continue;
            };
            if affinity < DEFAULT_PRIMARY_AFFINITY
                && (crush::hash32_pair(seed, osd.cast_unsigned()) >> 16) >= affinity
            {
                if position.is_none() {
                    position = Some(index);
                }
                continue;
            }
            position = Some(index);
            break;
        }

        let Some(index) = position else {
            return;
        };
        *primary = osds[index];
        if shift_primary && index > 0 {
            osds.copy_within(0..index, 1);
            osds[0] = *primary;
        }
    }

    fn exists(&self, osd: i32) -> bool {
        usize::try_from(osd)
            .ok()
            .and_then(|index| self.osd_state.get(index))
            .is_some_and(|state| state & (1 << 0) != 0)
    }

    fn is_up(&self, osd: i32) -> bool {
        usize::try_from(osd)
            .ok()
            .and_then(|index| self.osd_state.get(index))
            .is_some_and(|state| state & (1 << 0) != 0 && state & (1 << 1) != 0)
    }

    fn validate_placement_set(
        &self,
        name: &'static str,
        osds: &[i32],
        allow_duplicates: bool,
    ) -> Result<()> {
        let mut seen = HashSet::with_capacity(osds.len());
        for &osd in osds {
            if osd == CRUSH_ITEM_NONE {
                continue;
            }
            if !self.exists(osd) {
                return Err(MapError::UnsupportedPlacement(match name {
                    "pg_upmap" => "pg_upmap references nonexistent OSD",
                    "pg_temp" => "pg_temp references nonexistent OSD",
                    _ => "placement set references nonexistent OSD",
                }));
            }
            if !allow_duplicates && !seen.insert(osd) {
                return Err(MapError::UnsupportedPlacement(match name {
                    "pg_upmap" => "pg_upmap contains duplicate OSD",
                    "pg_temp" => "pg_temp contains duplicate OSD",
                    _ => "placement set contains duplicate OSD",
                }));
            }
        }
        Ok(())
    }
}

fn first_osd(osds: &[i32]) -> i32 {
    osds.iter()
        .copied()
        .find(|&osd| osd != CRUSH_ITEM_NONE)
        .unwrap_or(-1)
}

fn contains_osd(osds: &[i32], target: i32) -> bool {
    osds.contains(&target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, HashMap};

    use crate::crush::{
        BUCKET_STRAW2, HASH_RJENKINS1, MAGIC, RULE_EMIT, RULE_TAKE, RULE_TYPE_REPLICATED, RuleStep,
    };
    use crate::maps::{Fsid, OSDRemap, Pool, UTime};
    use crate::protocol::address::EntityAddrVec;
    use crate::wire::Encoder;

    fn test_pool(id: i64, pool_type: u8, size: u8) -> Pool {
        Pool {
            id,
            name: format!("pool-{id}"),
            pool_type,
            size,
            minimum_size: 0,
            crush_rule: 0,
            object_hash: OBJECT_HASH_RJENKINS,
            pg_count: 32,
            placement_pg_count: 32,
            stripe_width: 0,
            flags: POOL_FLAG_HASHPSPOOL,
            snapshot_sequence: 0,
            snapshots: BTreeMap::new(),
            erasure_code_profile: String::new(),
            application_metadata: HashMap::new(),
            options: HashMap::new(),
        }
    }

    fn test_osd_map(
        pool: Pool,
        osd_state: Vec<u32>,
        osd_weight: Vec<u32>,
        crush_data: Vec<u8>,
    ) -> OSDMap {
        let max_osd = i32::try_from(osd_state.len()).expect("osd count");
        let pool_id = pool.id;
        let pool_name = pool.name.clone();
        OSDMap {
            fsid: Fsid([0; 16]),
            epoch: 1,
            created: UTime::default(),
            modified: UTime::default(),
            pools: HashMap::from([(pool_id, pool)]),
            name_to_id: HashMap::from([(pool_name, pool_id)]),
            pool_max: pool_id,
            flags: 0,
            max_osd,
            osd_state,
            osd_weight,
            client_addresses: vec![
                EntityAddrVec(Vec::new());
                usize::try_from(max_osd).expect("max osd")
            ],
            pg_temp: HashMap::new(),
            primary_temp: HashMap::new(),
            primary_affinity: Vec::new(),
            crush_data,
            erasure_code_profiles: HashMap::new(),
            pg_upmap: HashMap::new(),
            pg_upmap_items: HashMap::new(),
            crush_version: 0,
            new_removed_snapshots: HashMap::new(),
            new_purged_snapshots: HashMap::new(),
            last_up_change: UTime::default(),
            last_in_change: UTime::default(),
            pg_upmap_primaries: HashMap::new(),
            crc: 0,
            crc_verified: false,
            applied_incremental: false,
        }
    }

    fn encode_placement_crush_map(name_count: u32) -> Vec<u8> {
        let mut encoder = Encoder::new(4_096);
        encoder.u32(MAGIC);
        encoder.i32(3);
        encoder.u32(1);
        encoder.i32(4);
        for (id, bucket_type, items) in [
            (-1, 2_u16, vec![-2, -3]),
            (-2, 1, vec![0, 1]),
            (-3, 1, vec![2, 3]),
        ] {
            encoder.u32(BUCKET_STRAW2);
            encoder.i32(id);
            encoder.u16(bucket_type);
            encoder.u8(u8::try_from(BUCKET_STRAW2).expect("algorithm fits"));
            encoder.u8(HASH_RJENKINS1);
            encoder.u32(u32::try_from(items.len()).expect("items") * 0x1_0000);
            encoder.u32(u32::try_from(items.len()).expect("items"));
            for item in &items {
                encoder.i32(*item);
            }
            for _ in &items {
                encoder.u32(0x1_0000);
            }
        }
        encoder.u32(1);
        encoder.u32(3);
        encoder.u8(0);
        encoder.u8(RULE_TYPE_REPLICATED);
        encoder.u8(1);
        encoder.u8(10);
        for step in [
            RuleStep {
                operation: RULE_TAKE,
                argument1: -1,
                argument2: 0,
            },
            RuleStep {
                operation: crate::crush::RULE_CHOOSE_FIRST_N,
                argument1: 0,
                argument2: 0,
            },
            RuleStep {
                operation: RULE_EMIT,
                argument1: 0,
                argument2: 0,
            },
        ] {
            encoder.u32(step.operation);
            encoder.i32(step.argument1);
            encoder.i32(step.argument2);
        }
        encoder.u32(name_count);
        for index in 0..name_count {
            encoder.i32(i32::try_from(index).expect("name index"));
            encoder.string(&format!("name-{index}"));
        }
        encoder.u32(0);
        encoder.u32(0);
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
        encoder.finish().expect("encode CRUSH")
    }

    fn encode_p00_crush_map() -> Vec<u8> {
        let mut encoder = Encoder::new(4_096);
        encoder.u32(MAGIC);
        encoder.i32(2);
        encoder.u32(1);
        encoder.i32(3);
        for (id, bucket_type, items) in [(-1, 10_u16, vec![-2]), (-2, 1, vec![0, 1, 2])] {
            encoder.u32(BUCKET_STRAW2);
            encoder.i32(id);
            encoder.u16(bucket_type);
            encoder.u8(u8::try_from(BUCKET_STRAW2).expect("algorithm fits"));
            encoder.u8(HASH_RJENKINS1);
            encoder.u32(u32::try_from(items.len()).expect("items") * 0x1_0000);
            encoder.u32(u32::try_from(items.len()).expect("items"));
            for item in &items {
                encoder.i32(*item);
            }
            for _ in &items {
                encoder.u32(0x1_0000);
            }
        }
        encoder.u32(1);
        encoder.u32(3);
        encoder.u8(0);
        encoder.u8(RULE_TYPE_REPLICATED);
        encoder.u8(1);
        encoder.u8(10);
        for step in [
            RuleStep {
                operation: RULE_TAKE,
                argument1: -1,
                argument2: 0,
            },
            RuleStep {
                operation: crate::crush::RULE_CHOOSE_FIRST_N,
                argument1: 0,
                argument2: 0,
            },
            RuleStep {
                operation: RULE_EMIT,
                argument1: 0,
                argument2: 0,
            },
        ] {
            encoder.u32(step.operation);
            encoder.i32(step.argument1);
            encoder.i32(step.argument2);
        }
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
        encoder.finish().expect("encode P00 CRUSH")
    }

    #[test]
    fn map_object_p00_oracle_vector() {
        let osd_map = test_osd_map(
            test_pool(2, POOL_TYPE_REPLICATED, 1),
            vec![],
            vec![],
            Vec::new(),
        );

        let placement = osd_map
            .map_object(2, b"p00-smoke-object", b"", b"")
            .expect("map object");

        assert_eq!(placement.raw_hash, 0x96fc_93a8);
        assert_eq!(placement.raw_pg.seed, 0x96fc_93a8);
        assert_eq!(placement.pg.seed, 8);
    }

    #[test]
    fn map_raw_hash_matches_object_placement() {
        let mut pool = test_pool(7, POOL_TYPE_REPLICATED, 1);
        pool.pg_count = 12;
        pool.placement_pg_count = 8;
        let osd_map = test_osd_map(pool, vec![], vec![], Vec::new());

        let object_placement = osd_map
            .map_object(7, b"object\xff", b"locator\xfe", b"namespace\xfd")
            .expect("map object");
        let raw_placement = osd_map
            .map_raw_hash(7, object_placement.raw_hash)
            .expect("map hash");

        assert_eq!(raw_placement, object_placement);
    }

    #[test]
    fn map_object_rejects_unsupported_pool_inputs() {
        let missing = test_osd_map(
            test_pool(2, POOL_TYPE_REPLICATED, 1),
            vec![],
            vec![],
            Vec::new(),
        );
        assert!(matches!(
            missing.map_object(-1, b"object", b"", b""),
            Err(MapError::UnsupportedPlacement(_))
        ));
        assert!(matches!(
            missing.map_object(9, b"object", b"", b""),
            Err(MapError::UnsupportedPlacement(_))
        ));

        let mut bad_hash = test_pool(1, POOL_TYPE_REPLICATED, 1);
        bad_hash.object_hash = 99;
        let osd_map = test_osd_map(bad_hash, vec![], vec![], Vec::new());
        assert!(matches!(
            osd_map.map_object(1, b"object", b"", b""),
            Err(MapError::UnsupportedPlacement(_))
        ));

        let mut bad_flags = test_pool(1, POOL_TYPE_REPLICATED, 1);
        bad_flags.flags = 0;
        let osd_map = test_osd_map(bad_flags, vec![], vec![], Vec::new());
        assert!(matches!(
            osd_map.map_object(1, b"object", b"", b""),
            Err(MapError::UnsupportedPlacement(_))
        ));

        let mut bad_geometry = test_pool(1, POOL_TYPE_REPLICATED, 1);
        bad_geometry.pg_count = 0;
        let osd_map = test_osd_map(bad_geometry, vec![], vec![], Vec::new());
        assert!(matches!(
            osd_map.map_object(1, b"object", b"", b""),
            Err(MapError::UnsupportedPlacement(_))
        ));
    }

    #[test]
    fn place_object_applies_up_and_acting_overrides() {
        let mut osd_map = test_osd_map(
            test_pool(2, POOL_TYPE_REPLICATED, 2),
            vec![3, 3, 3, 1],
            vec![0x1_0000, 0x1_0000, 0x1_0000, 0x1_0000],
            encode_placement_crush_map(0),
        );
        osd_map.primary_affinity = vec![
            DEFAULT_PRIMARY_AFFINITY,
            DEFAULT_PRIMARY_AFFINITY,
            0,
            DEFAULT_PRIMARY_AFFINITY,
        ];

        let identity = osd_map
            .map_object(2, b"p00-smoke-object", b"", b"")
            .expect("identity");
        osd_map.pg_upmap_items = HashMap::from([(identity.pg, vec![OSDRemap { from: 0, to: 2 }])]);
        osd_map.pg_upmap_primaries = HashMap::from([(identity.pg, 2)]);
        osd_map.pg_temp = HashMap::from([(identity.pg, vec![1, 3])]);
        osd_map.primary_temp = HashMap::from([(identity.pg, 1)]);

        let placement = osd_map
            .place_object(2, b"p00-smoke-object", b"", b"")
            .expect("place object");

        assert_eq!(placement.up, vec![0, 2]);
        assert_eq!(placement.up_primary, 0);
        assert_eq!(placement.acting, vec![1]);
        assert_eq!(placement.acting_primary, 1);
    }

    #[test]
    fn place_object_does_not_bound_crush_names_by_osd_count() {
        let osd_map = test_osd_map(
            test_pool(2, POOL_TYPE_REPLICATED, 1),
            vec![3, 3, 3, 3],
            vec![0x1_0000, 0x1_0000, 0x1_0000, 0x1_0000],
            encode_placement_crush_map(40),
        );

        osd_map
            .place_object(2, b"object", b"", b"")
            .expect("place object");
    }

    #[test]
    fn place_object_supports_erasure_pool_shard_set() {
        let osd_map = test_osd_map(
            test_pool(2, POOL_TYPE_ERASURE, 2),
            vec![3, 3, 3, 3],
            vec![0x1_0000, 0x1_0000, 0x1_0000, 0x1_0000],
            encode_placement_crush_map(0),
        );

        let placement = osd_map
            .place_object(2, b"object", b"", b"")
            .expect("place object");

        assert_eq!(placement.raw.len(), 2);
        assert_eq!(placement.up.len(), 2);
        assert_eq!(placement.acting.len(), 2);
        assert_eq!(placement.acting_primary, placement.acting[0]);
        assert!(placement.sharded);
        assert_eq!(placement.primary_shard, 0);
    }

    #[test]
    fn erasure_primary_affinity_preserves_shard_positions() {
        let mut osd_map = test_osd_map(
            test_pool(2, POOL_TYPE_ERASURE, 2),
            vec![3, 3, 3, 3],
            vec![0x1_0000, 0x1_0000, 0x1_0000, 0x1_0000],
            encode_placement_crush_map(0),
        );
        let baseline = osd_map
            .place_object(2, b"object", b"", b"")
            .expect("baseline placement");
        osd_map.primary_affinity = vec![DEFAULT_PRIMARY_AFFINITY; 4];
        osd_map.primary_affinity[usize::try_from(baseline.up[0]).expect("OSD index")] = 0;

        let placement = osd_map
            .place_object(2, b"object", b"", b"")
            .expect("affinity placement");

        assert_eq!(placement.up, baseline.up);
        assert_eq!(placement.acting, baseline.acting);
        assert_eq!(placement.up_primary, baseline.up[1]);
        assert_eq!(placement.acting_primary, baseline.acting[1]);
        assert_eq!(placement.primary_shard, 1);
    }

    #[test]
    fn place_object_rejects_invalid_replica_and_temporary_primary() {
        let mut osd_map = test_osd_map(
            test_pool(2, POOL_TYPE_REPLICATED, 0),
            vec![3, 3, 3, 3],
            vec![0x1_0000, 0x1_0000, 0x1_0000, 0x1_0000],
            encode_placement_crush_map(0),
        );

        assert!(matches!(
            osd_map.place_object(2, b"object", b"", b""),
            Err(MapError::UnsupportedPlacement(_))
        ));

        osd_map.pools.get_mut(&2).expect("pool").size = 2;
        let identity = osd_map
            .map_object(2, b"object", b"", b"")
            .expect("identity");
        osd_map.primary_temp = HashMap::from([(identity.pg, 3)]);
        osd_map.osd_state[3] = 1;
        assert!(matches!(
            osd_map.place_object(2, b"object", b"", b""),
            Err(MapError::UnsupportedPlacement(_))
        ));

        osd_map.primary_temp.clear();
        osd_map.pg_temp = HashMap::from([(identity.pg, vec![0, 0])]);
        assert!(matches!(
            osd_map.place_object(2, b"object", b"", b""),
            Err(MapError::UnsupportedPlacement(_))
        ));

        osd_map.pg_temp.clear();
        osd_map.pg_upmap = HashMap::from([(identity.pg, vec![0, 99])]);
        assert!(matches!(
            osd_map.place_object(2, b"object", b"", b""),
            Err(MapError::UnsupportedPlacement(_))
        ));
    }

    #[test]
    fn place_object_p00_live_oracle_vector() {
        let osd_map = test_osd_map(
            test_pool(2, POOL_TYPE_REPLICATED, 3),
            vec![3, 3, 3],
            vec![0x1_0000, 0x1_0000, 0x1_0000],
            encode_p00_crush_map(),
        );

        let placement = osd_map
            .place_object(2, b"p00-smoke-object", b"", b"")
            .expect("place object");

        assert_eq!(placement.pg.seed, 8);
        assert_eq!(placement.up, vec![0, 2, 1]);
        assert_eq!(placement.up_primary, 0);
        assert_eq!(placement.acting, vec![0, 2, 1]);
        assert_eq!(placement.acting_primary, 0);
    }

    #[test]
    fn rejected_full_upmap_skips_later_overrides() {
        let osd_map = OSDMap {
            fsid: Fsid([0; 16]),
            epoch: 1,
            created: UTime::default(),
            modified: UTime::default(),
            pools: HashMap::new(),
            name_to_id: HashMap::new(),
            pool_max: 0,
            flags: 0,
            max_osd: 3,
            osd_state: vec![3, 3, 3],
            osd_weight: vec![0x1_0000, 0, 0x1_0000],
            client_addresses: vec![EntityAddrVec(Vec::new()); 3],
            pg_temp: HashMap::new(),
            primary_temp: HashMap::new(),
            primary_affinity: Vec::new(),
            crush_data: Vec::new(),
            erasure_code_profiles: HashMap::new(),
            pg_upmap: HashMap::from([(
                PG {
                    pool: 2,
                    seed: 8,
                    preferred: -1,
                },
                vec![1, 2],
            )]),
            pg_upmap_items: HashMap::from([(
                PG {
                    pool: 2,
                    seed: 8,
                    preferred: -1,
                },
                vec![OSDRemap { from: 0, to: 2 }],
            )]),
            crush_version: 0,
            new_removed_snapshots: HashMap::new(),
            new_purged_snapshots: HashMap::new(),
            last_up_change: UTime::default(),
            last_in_change: UTime::default(),
            pg_upmap_primaries: HashMap::from([(
                PG {
                    pool: 2,
                    seed: 8,
                    preferred: -1,
                },
                2,
            )]),
            crc: 0,
            crc_verified: false,
            applied_incremental: false,
        };

        let pg = PG {
            pool: 2,
            seed: 8,
            preferred: -1,
        };
        assert_eq!(osd_map.apply_upmap(pg, &[0, 2]), vec![0, 2]);
    }

    #[test]
    fn upmap_items_can_replace_nonexistent_raw_osd() {
        let osd_map = OSDMap {
            fsid: Fsid([0; 16]),
            epoch: 1,
            created: UTime::default(),
            modified: UTime::default(),
            pools: HashMap::new(),
            name_to_id: HashMap::new(),
            pool_max: 0,
            flags: 0,
            max_osd: 3,
            osd_state: vec![0, 3, 3],
            osd_weight: vec![0x1_0000, 0x1_0000, 0x1_0000],
            client_addresses: vec![EntityAddrVec(Vec::new()); 3],
            pg_temp: HashMap::new(),
            primary_temp: HashMap::new(),
            primary_affinity: Vec::new(),
            crush_data: Vec::new(),
            erasure_code_profiles: HashMap::new(),
            pg_upmap: HashMap::new(),
            pg_upmap_items: HashMap::from([(
                PG {
                    pool: 2,
                    seed: 8,
                    preferred: -1,
                },
                vec![OSDRemap { from: 0, to: 2 }],
            )]),
            crush_version: 0,
            new_removed_snapshots: HashMap::new(),
            new_purged_snapshots: HashMap::new(),
            last_up_change: UTime::default(),
            last_in_change: UTime::default(),
            pg_upmap_primaries: HashMap::new(),
            crc: 0,
            crc_verified: false,
            applied_incremental: false,
        };

        let pg = PG {
            pool: 2,
            seed: 8,
            preferred: -1,
        };
        osd_map.validate_upmap(pg).expect("validate upmap");
        let raw = vec![0, 1];
        let mapped = osd_map.apply_upmap(pg, &raw);
        assert_eq!(raw, vec![0, 1]);
        assert_eq!(osd_map.only_up(&mapped, false), vec![2, 1]);
    }
}
