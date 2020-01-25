use crate::Error;
mod unconfirmed_request_pdu;
use unconfirmed_request_pdu::*;
mod tag;
use tag::*;

pub fn parse_apdu(bytes: &[u8]) -> Result<APDU, Error> {
    if bytes.is_empty() {
        return Err(Error::Length("empty apdu bytes"));
    }
    Ok(APDU {
        bytes,
        pdu_type: bytes[0],
    })
}

pub struct APDU<'a> {
    pub bytes: &'a [u8],
    pdu_type: u8,
}

impl<'a> APDU<'a> {
    pub fn pdu_type(&self) -> PDUType {
        self.pdu_type.into()
    }
    pub fn pdu_type_byte(&self) -> u8 {
        self.pdu_type
    }
}

/// Classification of APDU service. There are multiple services within each PDU type.
pub enum PDUType {
    BACnetConfirmedRequestPDU,
    BACnetUnconfirmedRequestPDU,
    BACnetSimpleACKPDU,
    BACnetComplexACKPDU,
    Segment,
    Error,
    RejectPDU,
    Abort,
    Reserved,
}

impl From<u8> for PDUType {
    fn from(b: u8) -> Self {
        match b & 0xF0 {
            0x00 => Self::BACnetConfirmedRequestPDU,
            0x10 => Self::BACnetUnconfirmedRequestPDU,
            0x20 => Self::BACnetSimpleACKPDU,
            0x30 => Self::BACnetComplexACKPDU,
            0x40 => Self::Segment,
            0x50 => Self::Error,
            0x60 => Self::RejectPDU,
            0x70 => Self::Abort,
            0x80..=0xF0 => Self::Reserved,
            // Safety: the byte is bitwise ANDed  with 0xF0, thus anything without a zero in the
            // lower nibble need not be checked.
            _ => unsafe { core::hint::unreachable_unchecked() },
        }
    }
}

pub enum ConfirmedServiceChoice {
    SubscribeCOV,
    ReadProperty,
    ReadPropertyMultiple,
    WriteProperty,
    WritePropertyMultiple,
    DeviceCommunicationControl,
    ReinitializeDevice,
    Unknown,
}

impl From<u8> for ConfirmedServiceChoice {
    fn from(b: u8) -> Self {
        match b {
            0x05 => Self::SubscribeCOV,
            0x0c => Self::ReadProperty,
            0x0e => Self::ReadPropertyMultiple,
            0x0f => Self::WriteProperty,
            0x10 => Self::WritePropertyMultiple,
            0x11 => Self::DeviceCommunicationControl,
            0x14 => Self::ReinitializeDevice,
            _ => Self::Unknown,
        }
    }
}

pub enum BACnetRejectReason {
    Other,
    BufferOverflow,
    InconsistentParameters,
    InvalidParameterDataType,
    InvalidTag,
    MissingRequiredParameter,
    ParameterOutOfRange,
    TooManyArguments,
    UndefinedEnumeration,
    UnrecognizedService,
    Unknown,
}

impl From<u8> for BACnetRejectReason {
    fn from(b: u8) -> Self {
        match b {
            0 => Self::Other,
            1 => Self::BufferOverflow,
            2 => Self::InconsistentParameters,
            3 => Self::InvalidParameterDataType,
            4 => Self::InvalidTag,
            5 => Self::MissingRequiredParameter,
            6 => Self::ParameterOutOfRange,
            7 => Self::TooManyArguments,
            8 => Self::UndefinedEnumeration,
            9 => Self::UnrecognizedService,
            _ => Self::Unknown,
        }
    }
}

pub struct ErrorPDU {
    invoke_id: u8,
    error_class: u8,
    error_code: u8,
}

impl ErrorPDU {
    fn parse(b: &[u8]) -> Result<Self, Error> {
        if b.len() != 3 {
            return Err(Error::Length("wrong len for ErrorPDU"));
        }
        Ok(Self {
            invoke_id: b[0],
            error_class: b[1],
            error_code: b[2],
        })
    }
    pub fn invoke_id(&self) -> u8 {
        self.invoke_id
    }
    pub fn error_class(&self) -> u8 {
        self.error_class
    }
    pub fn error_code(&self) -> u8 {
        self.error_code
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    #[test]
    fn basic_whois_test() {
        let bytes: &[u8] = &[
            0x81, 0x0b, 0x00, 0x1b, 0x01, 0x28, 0xff, 0xff, 0x00, 0x27, 0x2f, 0x06, 0x00, 0x40,
            0xae, 0x04, 0xd3, 0xff, 0xfe, 0x10, 0x08, 0x0a, 0x0b, 0x54, 0x1a, 0x0b, 0x54,
        ];
        let bvlc = parse_bvlc(&bytes).unwrap();
        let npdu = bvlc.npdu().as_ref().unwrap();
        let apdu = parse_apdu(npdu.payload()).unwrap();
        let ucs = UnconfirmedServiceChoice::parse(&apdu).unwrap();
        match ucs {
            UnconfirmedServiceChoice::WhoIs(lims) => {
                let lims = lims.unwrap();
                assert_eq!(lims.low_limit, 2900);
                assert_eq!(lims.high_limit, 2900);
            }
            _ => panic!("should be WhoIs"),
        }
    }
}
