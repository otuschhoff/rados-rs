const NAMESPACE_SEPARATOR: u8 = 0x1f;

pub(crate) fn object_hash(object: &[u8], locator: &[u8], namespace: &[u8]) -> u32 {
    let key = if locator.is_empty() { object } else { locator };
    if namespace.is_empty() {
        return rjenkins(key);
    }
    let mut value = Vec::with_capacity(namespace.len() + 1 + key.len());
    value.extend_from_slice(namespace);
    value.push(NAMESPACE_SEPARATOR);
    value.extend_from_slice(key);
    rjenkins(&value)
}

pub(crate) fn stable_mod(value: u32, count: u32) -> u32 {
    if count == 0 {
        return 0;
    }
    let mask = 1_u32
        .checked_shl(32 - (count - 1).leading_zeros())
        .unwrap_or(0)
        .wrapping_sub(1);
    if value & mask < count {
        value & mask
    } else {
        value & (mask >> 1)
    }
}

pub(crate) fn hash32_pair(mut first: u32, mut second: u32) -> u32 {
    let mut hash = 0x4e67_c6a7 ^ first ^ second;
    (first, second, hash) = mix(first, second, hash);
    (_, _, hash) = mix(231_232, first, hash);
    (_, _, hash) = mix(second, 1_232, hash);
    hash
}

pub(crate) fn hash32_triple(mut first: u32, mut second: u32, mut third: u32) -> u32 {
    let mut hash = 0x4e67_c6a7 ^ first ^ second ^ third;
    let mut x = 231_232;
    let mut y = 1_232;
    (first, second, hash) = mix(first, second, hash);
    (third, x, hash) = mix(third, x, hash);
    (y, _, hash) = mix(y, first, hash);
    (_, _, hash) = mix(second, x, hash);
    (_, _, hash) = mix(y, third, hash);
    hash
}

fn rjenkins(value: &[u8]) -> u32 {
    let (mut first, mut second, mut hash) = (0x9e37_79b9_u32, 0x9e37_79b9_u32, 0_u32);
    let (chunks, remainder) = value.as_chunks::<12>();
    for chunk in chunks {
        first = first.wrapping_add(u32::from_le_bytes(chunk[0..4].try_into().expect("chunk")));
        second = second.wrapping_add(u32::from_le_bytes(chunk[4..8].try_into().expect("chunk")));
        hash = hash.wrapping_add(u32::from_le_bytes(chunk[8..12].try_into().expect("chunk")));
        (first, second, hash) = mix(first, second, hash);
    }
    hash = hash.wrapping_add(u32::try_from(value.len()).unwrap_or(u32::MAX));
    for (index, byte) in remainder.iter().copied().enumerate() {
        let (target, shift) = match index {
            0..=3 => (&mut first, index * 8),
            4..=7 => (&mut second, (index - 4) * 8),
            _ => (&mut hash, (index - 7) * 8),
        };
        *target = target.wrapping_add(u32::from(byte) << shift);
    }
    mix(first, second, hash).2
}

fn mix(mut first: u32, mut second: u32, mut third: u32) -> (u32, u32, u32) {
    first = first.wrapping_sub(second).wrapping_sub(third) ^ (third >> 13);
    second = second.wrapping_sub(third).wrapping_sub(first) ^ first.wrapping_shl(8);
    third = third.wrapping_sub(first).wrapping_sub(second) ^ (second >> 13);
    first = first.wrapping_sub(second).wrapping_sub(third) ^ (third >> 12);
    second = second.wrapping_sub(third).wrapping_sub(first) ^ first.wrapping_shl(16);
    third = third.wrapping_sub(first).wrapping_sub(second) ^ (second >> 5);
    first = first.wrapping_sub(second).wrapping_sub(third) ^ (third >> 3);
    second = second.wrapping_sub(third).wrapping_sub(first) ^ first.wrapping_shl(10);
    third = third.wrapping_sub(first).wrapping_sub(second) ^ (second >> 15);
    (first, second, third)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_hash_and_stable_mod_match_pinned_go_vectors() {
        let hash = object_hash(b"p00-smoke-object", b"", b"");
        assert_eq!(hash, 0x96fc_93a8);
        assert_eq!(stable_mod(hash, 32), 8);
        assert_eq!(
            object_hash(&[0x00, 0xff, 0x80, b'o'], b"", &[b'n', 0x00, 0xfe]),
            0xa662_caa3
        );
        assert_eq!(
            object_hash(&[0x00, 0xff], &[0x81, 0x00, 0x7f], &[0xff, 0x1f]),
            0x8144_448c
        );
        assert_eq!(
            object_hash(&[0xde, 0xad], &[0x81, 0x00, 0x7f], &[0xff, 0x1f]),
            0x8144_448c
        );
        assert_ne!(
            object_hash(b"object", b"", b"namespace"),
            object_hash(b"object", b"", b"")
        );
        assert_eq!(
            object_hash(b"object", b"locator", b"namespace"),
            object_hash(b"different", b"locator", b"namespace")
        );
        assert_eq!(object_hash(b"located", b"routing-key", b""), 0xcec9_41f3);
    }

    #[test]
    fn stable_mod_preserves_existing_non_power_of_two_positions() {
        for value in 0..256 {
            let mapped = stable_mod(value, 12);
            assert!(mapped < 12);
            if value < 8 {
                assert_eq!(mapped, value);
            }
        }
    }

    #[test]
    fn crush_integer_hashes_match_pinned_go_vectors() {
        for (first, second, third, expected) in [
            (0, 0, 0, 0x7a3b_f3b2),
            (1, 2, 3, 0x735a_d42b),
            (0xdead_beef, u32::MAX, 17, 0xe824_7cea),
            (123_456_789, 0xffff_fffe, 42, 0x6d58_9f4b),
        ] {
            assert_eq!(hash32_triple(first, second, third), expected);
        }
    }
}
