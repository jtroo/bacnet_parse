use super::{Tag, APDU};
use crate::Error;

pub enum UnconfirmedServiceChoice {
    IAm,
    IHave,
    WhoHas,
    WhoIs(Option<WhoIsLimits>),
    Unknown,
}

impl UnconfirmedServiceChoice {
    fn parse(apdu: &APDU) -> Result<Self, Error> {
        let bytes = apdu.bytes;
        if bytes.len() < 2 {
            return Err(Error::Length("wrong len for UnconfirmedServiceChoice"));
        }
        Ok(match bytes[1] {
            0x00 => Self::IAm,
            0x01 => Self::IHave,
            0x07 => Self::WhoHas,
            0x08 => Self::WhoIs(WhoIsLimits::parse(apdu)),
            _ => Self::Unknown,
        })
    }
}

pub struct WhoIsLimits {
    low_limit: i32,
    high_limit: i32,
}

impl WhoIsLimits {
    fn parse(apdu: &APDU) -> Option<Self> {
        match apdu.bytes.len() {
            // Safety:
            // This must called from UnconfirmedServiceChoice which validates that this must be an
            // APDU frame with at least 2 payload bytes available.
            0 | 1 => unsafe { core::hint::unreachable_unchecked() },
            2 => None,
            _ => {
                let (post_tag_bytes, tag) = Tag::parse(&apdu.bytes[2..]).ok()?;
                // TODO: do something with this tag
                Some(Self {
                    low_limit: 0,
                    high_limit: 0,
                })
            }
        }
    }
}
