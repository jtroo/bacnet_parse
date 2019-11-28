use crate::Error;
use arrayref::array_ref;

pub fn parse_apdu(bytes: &[u8]) -> Result<APDU, Error> {
    if bytes.is_empty() {
        return Err(Error::Length("empty apdu bytes"));
    }
    Ok(match bytes[0] & 0xF0 {
        0x00 => APDU::BACnetConfirmedRequestPDU,
        0x10 => APDU::BACnetUnconfirmedRequestPDU(UnconfirmedServiceChoice::parse(&bytes[1..])?),
        0x20 => APDU::BACnetSimpleACKPDU,
        0x30 => APDU::BACnetComplexACKPDU,
        0x40 => APDU::Segment,
        0x50 => APDU::Error(ErrorPDU::parse(&bytes[1..])?),
        0x60 => APDU::RejectPDU,
        0x70 => APDU::Abort,
        0x80..=0xF0 => APDU::Reserved,
        _ => unsafe { core::hint::unreachable_unchecked() },
    })
}

/// Classification of APDU service. There are multiple services within each PDU type.
pub enum APDU {
    BACnetConfirmedRequestPDU,
    BACnetUnconfirmedRequestPDU(UnconfirmedServiceChoice),
    BACnetSimpleACKPDU,
    BACnetComplexACKPDU,
    Segment,
    Error(ErrorPDU),
    RejectPDU,
    Abort,
    Reserved,
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

pub enum UnconfirmedServiceChoice {
    IAm,
    IHave,
    WhoHas,
    WhoIs,
    Unknown,
}

impl UnconfirmedServiceChoice {
    fn parse(b: &[u8]) -> Result<Self, Error> {
        if b.is_empty() {
            return Err(Error::Length("wrong len for UnconfirmedServiceChoice"));
        }
        Ok(match b[1] {
            0x00 => Self::IAm,
            0x01 => Self::IHave,
            0x07 => Self::WhoHas,
            0x08 => Self::WhoIs,
            _ => Self::Unknown,
        })
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
