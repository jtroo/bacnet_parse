use super::{Tag, APDU};
use crate::nsdu::parse_unsigned;
use crate::Error;

pub enum UnconfirmedServiceChoice {
    IAm, // src/iam.c:77
    IHave,
    WhoHas,
    WhoIs(Option<WhoIsLimits>), // src/whois.c:69
    Unknown,
}

impl UnconfirmedServiceChoice {
    pub fn parse(apdu: &APDU) -> Result<Self, Error> {
        let bytes = apdu.bytes;
        if bytes.len() < 2 {
            return Err(Error::Length("wrong len for UnconfirmedServiceChoice"));
        }
        Ok(match bytes[1] {
            0x00 => Self::IAm,
            0x01 => Self::IHave,
            0x07 => Self::WhoHas,
            0x08 => Self::WhoIs(WhoIsLimits::parse(apdu)?),
            _ => Self::Unknown,
        })
    }
}

pub struct WhoIsLimits {
    pub low_limit: u32,
    pub high_limit: u32,
}

impl WhoIsLimits {
    /// Attempt to parse WhoIsLimits from an APDU payload.
    fn parse(apdu: &APDU) -> Result<Option<Self>, Error> {
        match apdu.bytes.len() {
            // Safety:
            // This must called from UnconfirmedServiceChoice which validates that this must be an
            // APDU frame with at least 2 payload bytes available.
            0 | 1 => unsafe { core::hint::unreachable_unchecked() },
            2 => Ok(None),
            _ => {
                // 1. parse a tag, starting from after the pdu type and service choice
                // 2. parse an unsigned value. The tag's value here is the length of the unsigned
                //    integer. This is the low value.
                // 3. parse another tag
                // 4. parse another unsigned value. This is the high value.
                let (bytes, tag) = Tag::parse(&apdu.bytes[2..])?;
                if tag.number != 0 {
                    return Err(Error::InvalidValue("Non-zero tag number in WhoIs"));
                }
                let (bytes, low_limit) = parse_unsigned(bytes, tag.value)?;
                let (bytes, tag) = Tag::parse(bytes)?;
                let (bytes, high_limit) = parse_unsigned(bytes, tag.value)?;
                Ok(Some(Self { low_limit, high_limit }))
            }
        }
    }
}
