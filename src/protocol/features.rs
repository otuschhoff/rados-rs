#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct GlobalFeatures(pub(crate) u64);

impl GlobalFeatures {
    pub(crate) const MONITOR_NAMES: Self = Self(1 << 5);
    pub(crate) const MONITOR_ENCODING: Self = Self(1 << 15);
    pub(crate) const PGID64: Self = Self(1 << 9);
    pub(crate) const SERVER_NAUTILUS: Self = Self(1 << 2);
    pub(crate) const SERVER_MIMIC_INCARNATION: Self = Self((1 << 57) | (1 << 28));
    pub(crate) const SERVER_NAUTILUS_MASK: Self =
        Self(Self::SERVER_NAUTILUS.0 | Self::SERVER_MIMIC_INCARNATION.0);
    pub(crate) const SERVER_OCTOPUS_MASK: Self = Self((1 << 16) | Self::SERVER_MIMIC_INCARNATION.0);
    pub(crate) const MESSAGE_ADDRESS_V2: Self = Self(1 << 59);
    pub(crate) const OSD_REPLY_MUX: Self = Self(1 << 12);
    pub(crate) const NEW_OSD_OP_ENCODING: Self = Self(1 << 56);
    pub(crate) const NEW_OSD_OP_REPLY_ENCODING: Self = Self(1 << 58);
    pub(crate) const CRUSH_V2: Self = Self(1 << 36);
    pub(crate) const RESERVED: Self = Self(1 << 62);
    pub(crate) const OSD_MAP_ENCODING: Self = Self(0x0f04_0880_9021_2a04);
    pub(crate) const MONITOR_CLIENT: Self = Self(0x2f07_0a92_d235_ea24);
    pub(crate) const OSD_CLIENT: Self = Self(0x2f07_0a92_d235_fa24);

    pub(crate) const fn contains(self, mask: Self) -> bool {
        self.0 & mask.0 == mask.0
    }
}

impl std::ops::BitOr for GlobalFeatures {
    type Output = Self;

    fn bitor(self, right: Self) -> Self::Output {
        Self(self.0 | right.0)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct MessengerFeatures(pub(crate) u64);

impl MessengerFeatures {
    pub(crate) const REVISION_1: Self = Self(1 << 0);
    pub(crate) const COMPRESSION: Self = Self(1 << 1);

    pub(crate) const fn contains(self, mask: Self) -> bool {
        self.0 & mask.0 == mask.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_match_the_frozen_go_contract() {
        assert_eq!(GlobalFeatures::OSD_MAP_ENCODING.0, 0x0f04_0880_9021_2a04);
        assert_eq!(GlobalFeatures::MONITOR_CLIENT.0, 0x2f07_0a92_d235_ea24);
        assert_eq!(GlobalFeatures::OSD_CLIENT.0, 0x2f07_0a92_d235_fa24);
        let required = GlobalFeatures::MONITOR_NAMES
            | GlobalFeatures::MONITOR_ENCODING
            | GlobalFeatures::PGID64
            | GlobalFeatures::MESSAGE_ADDRESS_V2
            | GlobalFeatures::SERVER_NAUTILUS_MASK;
        assert!(GlobalFeatures::MONITOR_CLIENT.contains(required));
        assert!(GlobalFeatures::OSD_CLIENT.contains(GlobalFeatures::CRUSH_V2));
        assert!(!GlobalFeatures::MONITOR_CLIENT.contains(GlobalFeatures::RESERVED));
        assert!(MessengerFeatures(3).contains(MessengerFeatures::REVISION_1));
        assert!(MessengerFeatures(3).contains(MessengerFeatures::COMPRESSION));
    }
}
