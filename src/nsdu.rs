pub mod apdu;
pub mod object_type;
pub mod property_id;
pub mod rpdu;
use crate::Error;
pub use apdu::parse_apdu;
use arrayref::array_ref;
pub use rpdu::parse_rpdu;

fn parse_unsigned(bytes: &[u8], sz: u32) -> Result<(&[u8], u32), Error> {
    let sz = sz as usize;
    if sz > 4 || sz == 0 {
        return Err(Error::InvalidValue(
            "unsigned len value is 0 or greater than 4",
        ));
    }
    if bytes.len() < sz {
        return Err(Error::Length(
            "unsigned len value greater than remaining bytes",
        ));
    }
    let val = match sz {
        1 => bytes[0] as u32,
        2 => u16::from_be_bytes(*array_ref!(bytes, 0, 2)) as u32,
        3 => ((bytes[0] as u32) << 16 | (bytes[1] as u32) << 8 | bytes[2] as u32),
        4 => u32::from_be_bytes(*array_ref!(bytes, 0, 4)),
        // Safety: this value is checked at the beginning of the fn.
        _ => unsafe { core::hint::unreachable_unchecked() },
    };
    Ok((&bytes[sz..], val))
}
