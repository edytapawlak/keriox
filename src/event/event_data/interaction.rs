use super::super::sections::seal::*;
use crate::error::Error;
use crate::prefix::SelfAddressingPrefix;
use crate::state::{EventSemantics, IdentifierState};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
// #[serde(rename_all = "lowercase")]
pub struct InteractionEvent {
    #[serde(rename = "dig")]
    pub previous_event_hash: SelfAddressingPrefix,

    pub data: Vec<Seal>,
}

impl EventSemantics for InteractionEvent {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        Ok(IdentifierState { ..state })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derivation::self_addressing::*;
    use crate::event::event_data::*;
    use crate::event::sections::seal;
    use crate::event::Event;
    use crate::event::SerializationFormats;
    use crate::prefix::IdentifierPrefix;
    use std::str::FromStr;

    #[test]
    fn test_assemble() {
        let seal_digest = SelfAddressing::Blake3_256.derive("ABCD".as_bytes());
        let event = Event {
            prefix: IdentifierPrefix::from_str("EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                .unwrap(),
            sn: 1,
            event_data: EventData::Ixn(InteractionEvent {
                previous_event_hash: SelfAddressingPrefix::from_str(
                    "EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                )
                .unwrap(),
                data: vec![Seal::Digest(DigestSeal {
                    dig: seal_digest.clone(),
                })],
            }),
        };

        match event.event_data {
            EventData::Ixn(ixn) => match ixn.data.first().unwrap() {
                Seal::Digest(seal) => assert!(seal.dig == seal_digest),
                _ => assert!(false),
            },
            _ => assert!(false),
        }
    }
}
