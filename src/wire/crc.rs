pub(crate) fn crc32c(seed: u32, payload: &[u8]) -> u32 {
    !crc32c::crc32c_append(!seed, payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_ceph_vectors_and_chaining() {
        assert_eq!(crc32c(0, b"foo bar baz"), 4_119_623_852);
        assert_eq!(crc32c(0, b"whiz bang boom"), 2_360_230_088);
        assert_eq!(crc32c(17, b""), 17);

        let first = crc32c(u32::MAX, b"foo ");
        assert_eq!(crc32c(first, b"bar baz"), crc32c(u32::MAX, b"foo bar baz"));
    }

    #[test]
    fn detects_bit_corruption() {
        let expected = crc32c(0, b"fixture");
        assert_ne!(crc32c(0, b"fixtuse"), expected);
    }
}
