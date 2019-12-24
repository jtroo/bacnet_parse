use super::APDU;
use crate::Error;

pub enum UnconfirmedServiceChoice {
    IAm,
    IHave,
    WhoHas,
    WhoIs,
    Unknown,
}

impl UnconfirmedServiceChoice {
    fn parse(apdu: &APDU) -> Result<Self, Error> {
        let bytes = apdu.bytes;
        if bytes.len() < 3 {
            return Err(Error::Length("wrong len for UnconfirmedServiceChoice"));
        }
        Ok(match bytes[1] {
            0x00 => Self::IAm,
            0x01 => Self::IHave,
            0x07 => Self::WhoHas,
            0x08 => Self::WhoIs,
            _ => Self::Unknown,
        })
    }
}
