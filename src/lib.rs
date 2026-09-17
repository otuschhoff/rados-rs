#![forbid(unsafe_code)]

#[cfg(test)]
mod entity_name;

#[cfg(test)]
mod tests {
    use crate::entity_name::{ENTITY_NAME_LENGTH, EntityName};

    #[test]
    fn decodes_and_round_trips_native_client_fixture() {
        let fixture = include_bytes!("../testdata/p01/entity-name-client-1.bin");
        let name = EntityName::decode(fixture).expect("native fixture must decode");

        assert_eq!(name.entity_type(), 8);
        assert_eq!(name.number(), 1);
        assert_eq!(name.encode().as_slice(), fixture);
    }

    #[test]
    fn decodes_signed_new_monitor_identity() {
        let fixture = include_bytes!("../testdata/p01/entity-name-mon-new.bin");
        let name = EntityName::decode(fixture).expect("native fixture must decode");

        assert_eq!(name.entity_type(), 1);
        assert_eq!(name.number(), -1);
        assert_eq!(name.encode().as_slice(), fixture);
    }

    #[test]
    fn rejects_non_exact_entity_name_lengths() {
        assert!(EntityName::decode(&[]).is_err());
        assert!(EntityName::decode(&[0; ENTITY_NAME_LENGTH - 1]).is_err());
        assert!(EntityName::decode(&[0; ENTITY_NAME_LENGTH + 1]).is_err());
    }
}
