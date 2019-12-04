use crate::Error;

pub fn parse_apdu(bytes: &[u8]) -> Result<APDU, Error> {
    if bytes.is_empty() {
        return Err(Error::Length("empty apdu bytes"));
    }
    Ok(APDU{bytes, pdu_type: bytes[0]})
}

pub struct APDU<'a> {
    bytes: &'a [u8],
    pdu_type: u8,
}

impl <'a>APDU<'a> {
    pub fn pdu_type(&self) -> PDUType {
        self.pdu_type.into()
    }
    pub fn pdu_type_byte(&self) -> u8 {
        self.pdu_type
    }
    pub fn bytes(&self) -> &'a[u8] {
        self.bytes
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
