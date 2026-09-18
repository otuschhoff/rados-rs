use std::sync::OnceLock;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

static CRUSH_LN_LH: OnceLock<Vec<u8>> = OnceLock::new();
static CRUSH_LN_LL: OnceLock<Vec<u8>> = OnceLock::new();

const CRUSH_LN_LH_BASE64: &str = concat!(
    "AAAAAAAAAAAAAALfyhbd4QAABbnloXC0AAAIjmjqiZoAAAtdabrHfgAADib9XIVV",
    "AAAQ6zifop8AABOqL90n8QAAFmP2+skTAAAZGKFuRjMAABvIQkCtqwAAHnLsEX+l",
    "AAAhGLEZtPMAACO5oy6qVgAAJlXTxPFcAAAo7VPzB+4AACuANHP3rQAALg6Fqd4E",
    "AAAwmFegXgcAADMdug784QAANZ68W2nZAAA4G22bspsAADqT3JhksgAAPQgXzpzU",
    "AAA/eC1yBNAAAEHkK27AwAAAREwfa0wtAABGsBbKR8EAAEkQHqw4HAAAS2xD8TZq",
    "AABNxJM6kzcAAFAZGOxsEQAAUmnhLzRuAABUtvfxMloAAFcAaOfvWgAAWUY/kZ3u",
    "AABbiIc2dDMAAF3HSun77AAAYAKVjFhxAABiOnHLgsgAAGRu6iR8XAAAZqAI5HiM",
    "AABozdgp/YEAAGr4YeX8fQAAbR+v3OIKAABvQ8unnkAAAHFkvrSlbQAAc4KSSOlh",
    "AAB1nU+Ay6gAAHe0/1EI2QAAecmqh51TAAB721nMo4gAAH3qFaMsGwAAf/Xmag/+",
    "AACB/tRcvMsAAIQE55P7gQAAhggoBrHVAACICJ2KnkcAAIoGT9UPKgAAjAFGe5S7",
    "AACN+Yj0roAAAI/vHph0CQAAkeIOoTk+AACT0mAsLl8AAJXAGjn71gAAl6tDr1n5",
    "AACZk+NVpOUAAJt5/9tsiwAAnV2f1QELAACfPsm8+4AAAKEdg/TDVQAAovnUxRA5",
    "AACk08JeaNwAAKarUtmedgAAqICMOEVHAACqU3RlKhwAAKwkETTE6QAArfJoZaih",
    "AACvvn+g8E0AALGIXHqpggAAs1AEcjxGAAC1FXzy0HgAALbYy1OwygAAuJn02Ktj",
    "AAC6WP6ycDoAALwV7f7tMgAAvdDHyagXAAC/iZEMFngAAMFATq3zgwAAwvUFhZPZ",
    "AADEp7pYN3wAAMZYcdpZ3QAAyAcwsAAWAADJs/ttBVkAAMte1pVlrwAAzQfGnYcC",
    "AADOrs/qgIUAANBT9tJgiQAA0fc/nHDAAADTmK6BeQYAANU4R6wApgAA1tYPOI5B",
    "AADYcgk15kMAANoMOaVIBAAA26SkeqmWAADdO02c8ksAAN7QOOYz8wAA4GNqI+Lu",
    "AADh9OUXDQIAAOOErXSPDgAA5RLG5UmYAADmnzUGVEgAAOgp+2kwRAAA6bMdk/mO",
    "AADrOp8Bl1AAAOzAgyHrMAAA7kTNWf+rAADvx4EENXkAAPFIoXBwCgAA8sgx5EEW",
    "AAD0RjWbE1MAAPXCr8ZURwAA9z2jjZ1KAAD4txQO27EAAPovBF54MgAA+6V3h319",
    "AAD9GnCLvhEAAP6N8mP5VwAA//8AAAAA"
);

const CRUSH_LN_LL_BASE64: &str = concat!(
    "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"
);

pub(crate) fn crush_ln(input: u32) -> u64 {
    let mut x = input.wrapping_add(1);
    let mut exponent = 15_u32;
    if x & 0x18_000 == 0 {
        let shift = (x & 0x1f_fff).leading_zeros() - 16;
        x <<= shift;
        exponent -= shift;
    }

    let coarse = x >> 8;
    let reciprocal = (1_u64 << 55).div_ceil(u64::from(coarse));
    let fraction = ((u64::from(x) * reciprocal) >> 48) & 0xff;
    let logarithm =
        table_u64(crush_ln_lh(), coarse - 128) + table_u64(crush_ln_ll(), fraction as u32);
    (u64::from(exponent) << 44) + (logarithm >> 4)
}

fn crush_ln_lh() -> &'static [u8] {
    CRUSH_LN_LH
        .get_or_init(|| {
            STANDARD
                .decode(CRUSH_LN_LH_BASE64)
                .expect("valid CRUSH ln table")
        })
        .as_slice()
}

fn crush_ln_ll() -> &'static [u8] {
    CRUSH_LN_LL
        .get_or_init(|| {
            STANDARD
                .decode(CRUSH_LN_LL_BASE64)
                .expect("valid CRUSH ln table")
        })
        .as_slice()
}

fn table_u64(table: &[u8], index: u32) -> u64 {
    let offset = usize::try_from(index).expect("table index") * 8;
    u64::from_be_bytes(table[offset..offset + 8].try_into().expect("table row"))
}

#[cfg(test)]
mod tests {
    use super::crush_ln;

    #[test]
    fn crush_ln_matches_pinned_vectors() {
        for (input, expected) in [
            (0, 0x0000_0000_0000_0000),
            (1, 0x0000_1000_0000_0000),
            (2, 0x0000_195c_01a3_9fbd),
            (255, 0x0000_8000_0000_0000),
            (256, 0x0000_8017_1e3b_6d7a),
            (32_767, 0x0000_f000_0000_0000),
            (65_534, 0x0000_ffff_fd61_ad10),
            (65_535, 0x0000_ffff_f000_0000),
        ] {
            assert_eq!(crush_ln(input), expected);
        }
    }
}
