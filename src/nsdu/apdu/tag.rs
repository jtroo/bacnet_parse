use crate::Error;
use arrayref::array_ref;

pub struct Tag {
    pub number: u8,
    pub value: u32,
}

impl Tag {
    /// Expects the byte array given to point to the start of a BACnet APDU tag starting from index
    /// 0. Returns a tuple of the byte slice after the tag as well as the tag information.
    pub fn parse(bytes: &[u8]) -> Result<(&[u8], Self), Error> {
        let (tag_bytes, number) = parse_tag_number(bytes)?;
        if is_extended_value(bytes[0]) {
            if tag_bytes.is_empty() {
                return Err(Error::Length("parsing tag"));
            }
            match bytes[0] {
                255 => {
                    if tag_bytes.len() < 4 {
                        return Err(Error::Length("parsing u32 tag"));
                    }
                    let value = u32::from_be_bytes(*array_ref!(tag_bytes, 0, 4));
                    Ok((&tag_bytes[4..], Self { number, value }))
                }
                254 => {
                    if tag_bytes.len() < 2 {
                        return Err(Error::Length("parsing u16 tag"));
                    }
                    let value = (u16::from_be_bytes(*array_ref!(tag_bytes, 0, 2))).into();
                    Ok((&tag_bytes[2..], Self { number, value }))
                }
                _value => Ok((
                    &tag_bytes[1..],
                    Self {
                        number,
                        value: tag_bytes[0].into(),
                    },
                )),
            }
        } else if is_opening_tag(bytes[0]) | is_closing_tag(bytes[0]) {
            Ok((tag_bytes, Self { number, value: 0 }))
        } else {
            let value = (bytes[0] & 0x07).into();
            Ok((tag_bytes, Self { number, value }))
        }
    }
}

fn parse_tag_number(bytes: &[u8]) -> Result<(&[u8], u8), Error> {
    if is_extended_tag_number(bytes[0]) {
        if bytes.len() < 2 {
            Err(Error::Length("cannot read tag"))
        } else {
            Ok((&bytes[2..], bytes[1]))
        }
    } else {
        if bytes.is_empty() {
            Err(Error::Length("cannot read tag"))
        } else {
            Ok((&bytes[1..], bytes[0] >> 4))
        }
    }
}

fn is_extended_tag_number(tagnum: u8) -> bool {
    tagnum & 0xF0 == 0xF0
}

/* from clause 20.2.1.3.1 Primitive Data */
fn is_extended_value(tagnum: u8) -> bool {
    tagnum & 0x07 == 5
}

/* from clause 20.2.1.1 Class */
fn is_context_specific(tagnum: u8) -> bool {
    tagnum & 0x08 == 0x08
}

/* from clause 20.2.1.3.2 Constructed Data */
fn is_opening_tag(tagnum: u8) -> bool {
    tagnum & 0x07 == 6
}

/* from clause 20.2.1.3.2 Constructed Data */
fn is_closing_tag(tagnum: u8) -> bool {
    tagnum & 0x07 == 7
}
