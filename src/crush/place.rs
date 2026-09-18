use super::{
    GraphError, Map, RULE_CHOOSE_FIRST_N, RULE_CHOOSE_INDEP, RULE_CHOOSELEAF_FIRST_N, RULE_EMIT,
    RULE_SET_CHOOSE_TRIES, RULE_SET_CHOOSELEAF_TRIES, RULE_TAKE, RULE_TYPE_ERASURE,
    RULE_TYPE_REPLICATED, Rule, RuleStep, crush_ln, hash32_pair, hash32_triple,
};

const ITEM_NONE: i32 = i32::MAX;
const MAX_CERTIFIED_REPLICAS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PlacementError;

struct Permutation {
    seed: u32,
    count: u32,
    items: Vec<u32>,
}

struct Placement<'a> {
    crush: &'a Map,
    weights: &'a [u32],
    permutations: std::collections::BTreeMap<i32, Permutation>,
}

impl Map {
    pub(crate) fn place(
        &self,
        rule_id: u32,
        seed: u32,
        replicas: usize,
        osd_weights: &[u32],
    ) -> Result<Vec<i32>, PlacementError> {
        if replicas == 0 || replicas > MAX_CERTIFIED_REPLICAS {
            return Err(PlacementError);
        }
        let Some(rule) = self.rules.get(&rule_id) else {
            return Err(PlacementError);
        };
        if rule.rule_type != RULE_TYPE_REPLICATED && rule.rule_type != RULE_TYPE_ERASURE {
            return Err(PlacementError);
        }
        self.validate_certified_rule(rule)?;
        self.validate_graph()
            .map_err(|_: GraphError| PlacementError)?;
        Placement {
            crush: self,
            weights: osd_weights,
            permutations: std::collections::BTreeMap::new(),
        }
        .rule(rule, seed, replicas)
    }

    fn validate_certified_rule(&self, rule: &Rule) -> Result<(), PlacementError> {
        let take_index = if rule.rule_type == RULE_TYPE_REPLICATED {
            if rule.steps.len() != 3
                || rule.steps[0].operation != RULE_TAKE
                || rule.steps[2]
                    != (RuleStep {
                        operation: RULE_EMIT,
                        argument1: 0,
                        argument2: 0,
                    })
            {
                return Err(PlacementError);
            }
            let choose = rule.steps[1];
            if choose
                != (RuleStep {
                    operation: RULE_CHOOSE_FIRST_N,
                    argument1: 0,
                    argument2: 0,
                })
                && (choose.operation != RULE_CHOOSELEAF_FIRST_N
                    || choose.argument1 != 0
                    || choose.argument2 <= 0
                    || !self.has_bucket_type(
                        u16::try_from(choose.argument2).map_err(|_| PlacementError)?,
                    ))
            {
                return Err(PlacementError);
            }
            0
        } else {
            if rule.steps.len() != 5
                || rule.steps[0]
                    != (RuleStep {
                        operation: RULE_SET_CHOOSELEAF_TRIES,
                        argument1: 5,
                        argument2: 0,
                    })
                || rule.steps[1]
                    != (RuleStep {
                        operation: RULE_SET_CHOOSE_TRIES,
                        argument1: 100,
                        argument2: 0,
                    })
                || rule.steps[2].operation != RULE_TAKE
                || rule.steps[3]
                    != (RuleStep {
                        operation: RULE_CHOOSE_INDEP,
                        argument1: 0,
                        argument2: 0,
                    })
                || rule.steps[4]
                    != (RuleStep {
                        operation: RULE_EMIT,
                        argument1: 0,
                        argument2: 0,
                    })
            {
                return Err(PlacementError);
            }
            2
        };

        let root = rule.steps[take_index].argument1;
        if !self.buckets.contains_key(&root) {
            return Err(PlacementError);
        }
        if self.class_shadow_buckets.contains(&root) {
            return Err(PlacementError);
        }
        if self.choose_local_tries != 0
            || self.choose_local_fallback_tries != 0
            || self.choose_total_tries != 50
            || self.chooseleaf_descend_once != 1
            || self.chooseleaf_vary_r != 1
            || !matches!(
                (self.straw_calc_version, self.allowed_bucket_algorithms),
                (0, 22) | (1, 54)
            )
            || self.chooseleaf_stable != 1
            || self.msr_descents != 100
            || self.msr_collision_tries != 100
        {
            return Err(PlacementError);
        }
        Ok(())
    }
}

impl Placement<'_> {
    #[allow(clippy::too_many_lines)]
    fn rule(
        &mut self,
        rule: &Rule,
        seed: u32,
        result_maximum: usize,
    ) -> Result<Vec<i32>, PlacementError> {
        let mut working = vec![ITEM_NONE; result_maximum];
        let mut output = vec![ITEM_NONE; result_maximum];
        let mut leaves = vec![ITEM_NONE; result_maximum];
        let mut working_size = 0_usize;
        let mut result = Vec::with_capacity(result_maximum);
        let mut choose_tries = self.crush.choose_total_tries + 1;
        let mut chooseleaf_tries = 0_u32;
        let mut recurse_tries = choose_tries;
        if self.crush.chooseleaf_descend_once != 0 {
            recurse_tries = 1;
        }

        for step in &rule.steps {
            match step.operation {
                RULE_SET_CHOOSE_TRIES => {
                    if step.argument1 > 0 {
                        choose_tries = step.argument1.cast_unsigned();
                    }
                }
                RULE_SET_CHOOSELEAF_TRIES => {
                    if step.argument1 > 0 {
                        chooseleaf_tries = step.argument1.cast_unsigned();
                    }
                }
                RULE_TAKE => {
                    if !self.valid_take(step.argument1) {
                        continue;
                    }
                    working[0] = step.argument1;
                    working_size = 1;
                }
                RULE_CHOOSE_FIRST_N | RULE_CHOOSELEAF_FIRST_N | RULE_CHOOSE_INDEP => {
                    if working_size == 0 {
                        continue;
                    }
                    let mut output_size = 0_usize;
                    for item in working.iter().take(working_size) {
                        let mut number = step.argument1;
                        if number <= 0 {
                            number += i32::try_from(result_maximum).map_err(|_| PlacementError)?;
                            if number <= 0 {
                                continue;
                            }
                        }
                        let Some(bucket) = self.crush.buckets.get(item) else {
                            continue;
                        };
                        let recurse_to_leaf = step.operation == RULE_CHOOSELEAF_FIRST_N;
                        if step.operation == RULE_CHOOSE_INDEP {
                            let count = usize::try_from(number)
                                .map_err(|_| PlacementError)?
                                .min(result_maximum.saturating_sub(output_size));
                            let recurse = if chooseleaf_tries == 0 {
                                1
                            } else {
                                chooseleaf_tries
                            };
                            self.choose_indep(
                                bucket,
                                seed,
                                count,
                                usize::try_from(number).map_err(|_| PlacementError)?,
                                step.argument2,
                                &mut output,
                                output_size,
                                choose_tries,
                                recurse,
                                recurse_to_leaf,
                                Some(&mut leaves),
                                0,
                            );
                            output_size += count;
                        } else {
                            let chosen = self.choose_first_n(
                                bucket,
                                seed,
                                usize::try_from(number).map_err(|_| PlacementError)?,
                                step.argument2,
                                &mut output,
                                output_size,
                                result_maximum.saturating_sub(output_size),
                                choose_tries,
                                recurse_tries,
                                self.crush.choose_local_tries,
                                self.crush.choose_local_fallback_tries,
                                recurse_to_leaf,
                                u32::from(self.crush.chooseleaf_vary_r),
                                self.crush.chooseleaf_stable != 0,
                                Some(&mut leaves),
                                0,
                            )?;
                            output_size += chosen;
                        }
                    }
                    if step.operation == RULE_CHOOSELEAF_FIRST_N {
                        output[..output_size].copy_from_slice(&leaves[..output_size]);
                    }
                    std::mem::swap(&mut working, &mut output);
                    working_size = output_size;
                }
                RULE_EMIT => {
                    let remaining = result_maximum
                        .saturating_sub(result.len())
                        .min(working_size);
                    result.extend_from_slice(&working[..remaining]);
                    working_size = 0;
                }
                _ => return Err(PlacementError),
            }
        }
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    fn choose_indep(
        &mut self,
        bucket: &super::map::Bucket,
        seed: u32,
        mut left: usize,
        replicas: usize,
        target_type: i32,
        output: &mut [i32],
        output_position: usize,
        tries: u32,
        recurse_tries: u32,
        recurse_to_leaf: bool,
        mut leaves: Option<&mut [i32]>,
        parent_r: usize,
    ) {
        let end = output_position + left;
        for position in output_position..end {
            output[position] = ITEM_NONE;
            if let Some(values) = leaves.as_deref_mut() {
                values[position] = ITEM_NONE;
            }
        }

        let mut failure = 0_u32;
        while left > 0 && failure < tries {
            for position in output_position..end {
                if output[position] != ITEM_NONE {
                    continue;
                }
                let mut current = bucket;
                loop {
                    let r = position
                        + parent_r
                        + replicas * usize::try_from(failure).expect("failure fits");
                    if current.items.is_empty() {
                        break;
                    }
                    let item = straw2_choose(current, seed, r);
                    if item >= self.crush.max_devices {
                        left -= 1;
                        break;
                    }

                    let mut item_type = 0_i32;
                    if item < 0 {
                        let Some(child) = self.crush.buckets.get(&item) else {
                            left -= 1;
                            break;
                        };
                        item_type = i32::from(child.bucket_type);
                    }
                    if item_type != target_type {
                        if item >= 0 {
                            left -= 1;
                            break;
                        }
                        current = &self.crush.buckets[&item];
                        continue;
                    }

                    if output[output_position..end].contains(&item) {
                        break;
                    }

                    if recurse_to_leaf {
                        if item < 0 {
                            if let Some(values) = leaves.as_deref_mut() {
                                self.choose_indep(
                                    &self.crush.buckets[&item],
                                    seed,
                                    1,
                                    replicas,
                                    0,
                                    values,
                                    position,
                                    recurse_tries,
                                    0,
                                    false,
                                    None,
                                    r,
                                );
                                if values[position] == ITEM_NONE {
                                    break;
                                }
                            }
                        } else if let Some(values) = leaves.as_deref_mut() {
                            values[position] = item;
                        }
                    }

                    if item_type == 0 && self.is_out(item, seed) {
                        break;
                    }
                    output[position] = item;
                    left -= 1;
                    break;
                }
            }
            failure += 1;
        }
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn choose_first_n(
        &mut self,
        bucket: &super::map::Bucket,
        seed: u32,
        replicas: usize,
        target_type: i32,
        output: &mut [i32],
        mut output_position: usize,
        output_size: usize,
        tries: u32,
        recurse_tries: u32,
        local_retries: u32,
        local_fallback_retries: u32,
        recurse_to_leaf: bool,
        vary_r: u32,
        stable: bool,
        mut leaves: Option<&mut [i32]>,
        parent_r: usize,
    ) -> Result<usize, PlacementError> {
        let mut count = output_size;
        let first_replica = if stable { 0 } else { output_position };
        for replica in first_replica..replicas {
            if count == 0 {
                break;
            }
            let mut total_failures = 0_u32;
            let mut skip_replica = false;
            let mut item = ITEM_NONE;
            let mut retry_descent = true;
            while retry_descent {
                retry_descent = false;
                let mut current = bucket;
                let mut local_failures = 0_u32;
                let mut retry_bucket = true;
                while retry_bucket {
                    retry_bucket = false;
                    let mut collide = false;
                    let mut reject = false;
                    let r =
                        replica + parent_r + usize::try_from(total_failures).expect("failures fit");
                    if current.items.is_empty() {
                        reject = true;
                    } else if local_fallback_retries > 0
                        && local_failures
                            >= u32::try_from(current.items.len() >> 1).expect("bucket size fits")
                        && local_failures > local_fallback_retries
                    {
                        item = self.permutation_choose(current, seed, r);
                    } else {
                        item = straw2_choose(current, seed, r);
                    }

                    if !reject && item >= self.crush.max_devices {
                        skip_replica = true;
                        break;
                    }

                    let mut item_type = 0_i32;
                    if !reject && item < 0 {
                        let Some(child) = self.crush.buckets.get(&item) else {
                            skip_replica = true;
                            break;
                        };
                        item_type = i32::from(child.bucket_type);
                    }
                    if !reject && item_type != target_type {
                        if item >= 0 {
                            skip_replica = true;
                            break;
                        }
                        current = &self.crush.buckets[&item];
                        retry_bucket = true;
                        continue;
                    }

                    if !reject {
                        collide = output[..output_position].contains(&item);
                    }

                    if !reject && !collide && recurse_to_leaf {
                        if item < 0 {
                            let sub_r = if vary_r != 0 { r >> (vary_r - 1) } else { 0 };
                            let recursive_replicas = if stable { 1 } else { output_position + 1 };
                            if let Some(values) = leaves.as_deref_mut() {
                                let chosen = self.choose_first_n(
                                    &self.crush.buckets[&item],
                                    seed,
                                    recursive_replicas,
                                    0,
                                    values,
                                    output_position,
                                    count,
                                    recurse_tries,
                                    0,
                                    local_retries,
                                    local_fallback_retries,
                                    false,
                                    vary_r,
                                    stable,
                                    None,
                                    sub_r,
                                )?;
                                if chosen <= output_position {
                                    reject = true;
                                }
                            }
                        } else if let Some(values) = leaves.as_deref_mut() {
                            values[output_position] = item;
                        }
                    }

                    if !reject && !collide && item_type == 0 {
                        reject = self.is_out(item, seed);
                    }
                    if reject || collide {
                        total_failures = total_failures.wrapping_add(1);
                        local_failures = local_failures.wrapping_add(1);
                        if (collide && local_failures <= local_retries)
                            || (local_fallback_retries > 0
                                && local_failures
                                    <= u32::try_from(current.items.len())
                                        .expect("bucket size fits")
                                        + local_fallback_retries)
                        {
                            retry_bucket = true;
                        } else if total_failures < tries {
                            retry_descent = true;
                        } else {
                            skip_replica = true;
                        }
                    }
                }
            }
            if skip_replica {
                continue;
            }
            output[output_position] = item;
            output_position += 1;
            count -= 1;
        }
        Ok(output_position)
    }

    fn permutation_choose(
        &mut self,
        bucket: &super::map::Bucket,
        seed: u32,
        replica: usize,
    ) -> i32 {
        let state = self
            .permutations
            .entry(bucket.id)
            .or_insert_with(|| Permutation {
                seed: 0,
                count: 0,
                items: vec![0; bucket.items.len()],
            });
        let position = u32::try_from(replica).expect("replica fits")
            % u32::try_from(bucket.items.len()).expect("bucket size fits");
        if state.seed != seed || state.count == 0 {
            state.seed = seed;
            if position == 0 {
                let selected = hash32_triple(seed, bucket.id.cast_unsigned(), 0)
                    % u32::try_from(bucket.items.len()).expect("bucket size fits");
                state.items[0] = selected;
                state.count = 0xffff;
                return bucket.items[usize::try_from(selected).expect("selection fits")];
            }
            for (index, item) in state.items.iter_mut().enumerate() {
                *item = u32::try_from(index).expect("index fits");
            }
            state.count = 0;
        } else if state.count == 0xffff {
            for index in 1..state.items.len() {
                state.items[index] = u32::try_from(index).expect("index fits");
            }
            let first = usize::try_from(state.items[0]).expect("first selection fits");
            state.items[first] = 0;
            state.count = 1;
        }

        while state.count <= position {
            let current = state.count;
            let len = u32::try_from(bucket.items.len()).expect("bucket size fits");
            if current < len - 1 {
                let offset =
                    hash32_triple(seed, bucket.id.cast_unsigned(), current) % (len - current);
                if offset != 0 {
                    let current_index = usize::try_from(current).expect("current fits");
                    let offset_index = usize::try_from(current + offset).expect("offset fits");
                    state.items.swap(current_index, offset_index);
                }
            }
            state.count += 1;
        }
        bucket.items[usize::try_from(
            state.items[usize::try_from(position).expect("position fits")],
        )
        .expect("selection fits")]
    }

    fn valid_take(&self, item: i32) -> bool {
        if item >= 0 {
            return item < self.crush.max_devices;
        }
        self.crush.buckets.contains_key(&item)
    }

    fn is_out(&self, item: i32, seed: u32) -> bool {
        if item < 0 {
            return true;
        }
        let Ok(index) = usize::try_from(item) else {
            return true;
        };
        let Some(&weight) = self.weights.get(index) else {
            return true;
        };
        if weight >= 0x1_0000 {
            return false;
        }
        if weight == 0 {
            return true;
        }
        (hash32_pair(seed, item.cast_unsigned()) & 0xffff) >= weight
    }
}

fn straw2_choose(bucket: &super::map::Bucket, seed: u32, replica: usize) -> i32 {
    let mut high = 0_usize;
    let mut high_draw = i64::MIN;
    for (index, &weight) in bucket.item_weights.iter().enumerate() {
        let mut draw = i64::MIN;
        if weight != 0 {
            let random = hash32_triple(
                seed,
                bucket.items[index].cast_unsigned(),
                u32::try_from(replica).expect("certified replica fits"),
            ) & 0xffff;
            let logarithm = crush_ln(random).cast_signed() - (1_i64 << 48);
            draw = logarithm / i64::from(weight);
        }
        if index == 0 || draw > high_draw {
            high = index;
            high_draw = draw;
        }
    }
    bucket.items[high]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crush::RULE_CHOOSELEAF_INDEP;

    fn test_placement_map() -> Map {
        Map {
            max_devices: 4,
            buckets: [
                (
                    -1,
                    super::super::map::Bucket {
                        id: -1,
                        bucket_type: 2,
                        weight: 4 * 0x1_0000,
                        items: vec![-2, -3],
                        item_weights: vec![2 * 0x1_0000, 2 * 0x1_0000],
                    },
                ),
                (
                    -2,
                    super::super::map::Bucket {
                        id: -2,
                        bucket_type: 1,
                        weight: 2 * 0x1_0000,
                        items: vec![0, 1],
                        item_weights: vec![0x1_0000, 0x1_0000],
                    },
                ),
                (
                    -3,
                    super::super::map::Bucket {
                        id: -3,
                        bucket_type: 1,
                        weight: 2 * 0x1_0000,
                        items: vec![2, 3],
                        item_weights: vec![0x1_0000, 0x1_0000],
                    },
                ),
            ]
            .into_iter()
            .collect(),
            rules: [(
                0,
                Rule {
                    rule_type: RULE_TYPE_REPLICATED,
                    min_size: 0,
                    max_size: 0,
                    steps: vec![
                        RuleStep {
                            operation: RULE_TAKE,
                            argument1: -1,
                            argument2: 0,
                        },
                        RuleStep {
                            operation: RULE_CHOOSE_FIRST_N,
                            argument1: 0,
                            argument2: 0,
                        },
                        RuleStep {
                            operation: RULE_EMIT,
                            argument1: 0,
                            argument2: 0,
                        },
                    ],
                },
            )]
            .into_iter()
            .collect(),
            choose_local_tries: 0,
            choose_local_fallback_tries: 0,
            choose_total_tries: 50,
            chooseleaf_descend_once: 1,
            chooseleaf_vary_r: 1,
            straw_calc_version: 0,
            allowed_bucket_algorithms: 22,
            chooseleaf_stable: 1,
            msr_descents: 100,
            msr_collision_tries: 100,
            class_shadow_buckets: std::collections::BTreeSet::new(),
        }
    }

    #[test]
    fn place_choose_first_n_returns_unique_osds() {
        let crush_map = test_placement_map();
        let weights = [0x1_0000; 4];
        for seed in 0..32_u32 {
            let got = crush_map
                .place(0, seed, 2, &weights)
                .expect("place choose firstn");
            assert_eq!(got.len(), 2);
            assert_ne!(got[0], got[1]);
            assert!((0..=3).contains(&got[0]));
            assert!((0..=3).contains(&got[1]));
        }
    }

    #[test]
    fn place_chooseleaf_first_n_returns_unique_leaves() {
        let mut crush_map = test_placement_map();
        crush_map.rules.insert(
            0,
            Rule {
                rule_type: RULE_TYPE_REPLICATED,
                min_size: 0,
                max_size: 0,
                steps: vec![
                    RuleStep {
                        operation: RULE_TAKE,
                        argument1: -1,
                        argument2: 0,
                    },
                    RuleStep {
                        operation: RULE_CHOOSELEAF_FIRST_N,
                        argument1: 0,
                        argument2: 1,
                    },
                    RuleStep {
                        operation: RULE_EMIT,
                        argument1: 0,
                        argument2: 0,
                    },
                ],
            },
        );
        for seed in 0..32_u32 {
            let got = crush_map
                .place(0, seed, 2, &[0x1_0000; 4])
                .expect("place chooseleaf firstn");
            assert_eq!(got.len(), 2);
            assert_ne!(got[0], got[1]);
            assert!(got[0] >= 0);
            assert!(got[1] >= 0);
        }
    }

    #[test]
    fn place_choose_indep_returns_unique_osds() {
        let mut crush_map = test_placement_map();
        crush_map.rules.insert(
            0,
            Rule {
                rule_type: RULE_TYPE_ERASURE,
                min_size: 0,
                max_size: 0,
                steps: vec![
                    RuleStep {
                        operation: RULE_SET_CHOOSELEAF_TRIES,
                        argument1: 5,
                        argument2: 0,
                    },
                    RuleStep {
                        operation: RULE_SET_CHOOSE_TRIES,
                        argument1: 100,
                        argument2: 0,
                    },
                    RuleStep {
                        operation: RULE_TAKE,
                        argument1: -1,
                        argument2: 0,
                    },
                    RuleStep {
                        operation: RULE_CHOOSE_INDEP,
                        argument1: 0,
                        argument2: 0,
                    },
                    RuleStep {
                        operation: RULE_EMIT,
                        argument1: 0,
                        argument2: 0,
                    },
                ],
            },
        );
        let weights = [0x1_0000; 4];
        for seed in 0..32_u32 {
            let got = crush_map.place(0, seed, 3, &weights).expect("place indep");
            assert_eq!(got.len(), 3);
            assert_ne!(got[0], got[1]);
            assert_ne!(got[0], got[2]);
            assert_ne!(got[1], got[2]);
        }
    }

    #[test]
    fn place_rejects_chooseleaf_indep() {
        let mut crush_map = test_placement_map();
        crush_map.rules.insert(
            0,
            Rule {
                rule_type: RULE_TYPE_ERASURE,
                min_size: 0,
                max_size: 0,
                steps: vec![
                    RuleStep {
                        operation: RULE_SET_CHOOSELEAF_TRIES,
                        argument1: 5,
                        argument2: 0,
                    },
                    RuleStep {
                        operation: RULE_SET_CHOOSE_TRIES,
                        argument1: 100,
                        argument2: 0,
                    },
                    RuleStep {
                        operation: RULE_TAKE,
                        argument1: -1,
                        argument2: 0,
                    },
                    RuleStep {
                        operation: RULE_CHOOSELEAF_INDEP,
                        argument1: 0,
                        argument2: 1,
                    },
                    RuleStep {
                        operation: RULE_EMIT,
                        argument1: 0,
                        argument2: 0,
                    },
                ],
            },
        );
        assert_eq!(
            crush_map.place(0, 7, 2, &[0x1_0000; 4]),
            Err(PlacementError)
        );
    }

    #[test]
    fn place_filters_out_weights() {
        let crush_map = test_placement_map();
        let got = crush_map
            .place(0, 7, 2, &[0, 0, 0, 0x1_0000])
            .expect("place with filtered weights");
        assert_eq!(got, vec![3]);
    }

    #[test]
    fn place_rejects_invalid_rule() {
        assert_eq!(
            test_placement_map().place(9, 0, 1, &[0x1_0000]),
            Err(PlacementError)
        );
    }

    #[test]
    fn place_rejects_invalid_replica_count() {
        let crush_map = test_placement_map();
        assert_eq!(crush_map.place(0, 0, 0, &[0x1_0000]), Err(PlacementError));
        assert_eq!(crush_map.place(0, 0, 65, &[0x1_0000]), Err(PlacementError));
    }

    #[test]
    fn place_rejects_cyclic_bucket_graph() {
        let mut crush_map = test_placement_map();
        crush_map.buckets.get_mut(&-2).expect("bucket").items[0] = -1;
        assert_eq!(crush_map.place(0, 0, 1, &[0x1_0000]), Err(PlacementError));
    }

    #[test]
    fn place_rejects_outside_certified_profile() {
        let cases: [fn(&mut Map); 8] = [
            |value| value.choose_total_tries = 51,
            |value| value.straw_calc_version = 2,
            |value| value.allowed_bucket_algorithms = 0,
            |value| value.msr_descents = 99,
            |value| value.msr_collision_tries = 99,
            |value| {
                value.rules.insert(
                    0,
                    Rule {
                        rule_type: RULE_TYPE_REPLICATED,
                        min_size: 0,
                        max_size: 0,
                        steps: vec![
                            RuleStep {
                                operation: RULE_TAKE,
                                argument1: -1,
                                argument2: 0,
                            },
                            RuleStep {
                                operation: RULE_CHOOSELEAF_FIRST_N,
                                argument1: 0,
                                argument2: 99,
                            },
                            RuleStep {
                                operation: RULE_EMIT,
                                argument1: 0,
                                argument2: 0,
                            },
                        ],
                    },
                );
            },
            |value| {
                value.class_shadow_buckets.insert(-1);
            },
            |value| {
                value.rules.get_mut(&0).expect("rule").steps[0].argument1 = -99;
            },
        ];

        for mutate in cases {
            let mut crush_map = test_placement_map();
            mutate(&mut crush_map);
            assert_eq!(
                crush_map.place(0, 1, 2, &[0x1_0000; 4]),
                Err(PlacementError)
            );
        }
    }

    #[test]
    fn place_rejects_excessive_bucket_depth() {
        let mut crush_map = test_placement_map();
        crush_map.buckets.clear();
        let maximum_depth =
            i32::try_from(super::super::map::MAX_CERTIFIED_DEPTH).expect("depth fits i32");
        for depth in 1..=(maximum_depth + 1) {
            let item = if depth <= maximum_depth {
                -depth - 1
            } else {
                0
            };
            crush_map.buckets.insert(
                -depth,
                super::super::map::Bucket {
                    id: -depth,
                    bucket_type: 1,
                    weight: 0x1_0000,
                    items: vec![item],
                    item_weights: vec![0x1_0000],
                },
            );
        }
        assert_eq!(crush_map.place(0, 1, 1, &[0x1_0000]), Err(PlacementError));
    }
}
