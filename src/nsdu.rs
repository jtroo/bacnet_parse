mod apdu;
mod rpdu;
pub use apdu::*;
pub use rpdu::*;

pub enum NSDU<'a> {
    APDU(APDU<'a>),
    RPDU(RPDU<'a>),
    Invalid,
}

impl Default for NSDU<'_> {
    fn default() -> Self {
        Self::Invalid
    }
}
