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

pub struct APDU<'a> {
    _bytes: &'a [u8],
}

pub struct RPDU<'a> {
    _bytes: &'a [u8],
}

pub enum NLMType {
    WhoIsRouterToNetwork,
    IAmRouterToNetwork,
    ICouldBeRouterToNetwork,
    RejectMessageToNetwork,
    RouterBusyToNetwork,
    RouterAvailableToNetwork,
    InitializeRoutingTable,
    InitializeRoutingTableACK,
    EstablishConnectionToNetwork,
    DisconnectConnectionToNetwork,
    ChallengeRequest,
    SecurityPayload,
    SecurityResponse,
    RequestKeyUpdate,
    UpdateKeySet,
    UpdateDistributionKey,
    RequestMasterKey,
    SetMasterKey,
    ReservedforusebyASHRAE,
    AvailableforVendorProprietaryMessages,
}

impl From<u8> for NLMType {
    fn from(b: u8) -> Self {
        match b {
            0x00 => Self::WhoIsRouterToNetwork,
            0x01 => Self::IAmRouterToNetwork,
            0x02 => Self::ICouldBeRouterToNetwork,
            0x03 => Self::RejectMessageToNetwork,
            0x04 => Self::RouterBusyToNetwork,
            0x05 => Self::RouterAvailableToNetwork,
            0x06 => Self::InitializeRoutingTable,
            0x07 => Self::InitializeRoutingTableACK,
            0x08 => Self::EstablishConnectionToNetwork,
            0x09 => Self::DisconnectConnectionToNetwork,
            0x0A => Self::ChallengeRequest,
            0x0B => Self::SecurityPayload,
            0x0C => Self::SecurityResponse,
            0x0D => Self::RequestKeyUpdate,
            0x0E => Self::UpdateKeySet,
            0x0F => Self::UpdateDistributionKey,
            0x10 => Self::RequestMasterKey,
            0x11 => Self::SetMasterKey,
            0x12..=0x7F => Self::ReservedforusebyASHRAE,
            0x80..=0xFF => Self::AvailableforVendorProprietaryMessages,
        }
    }
}
