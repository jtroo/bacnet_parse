use crate::Error;

pub fn parse_apdu(bytes: &[u8]) -> Result<APDU, Error> {
    // TODO
    Ok(APDU { bytes })
}

pub struct APDU<'a> {
    bytes: &'a [u8],
}

impl<'a> APDU<'a> {
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
}
