use crate::Error;
use arrayref::array_ref;

pub type DNET = u16;

fn try_parse_dnet(b: &[u8]) -> Result<DNET, Error> {
    if b.len() < 2 {
        Err(Error::Length("insufficient size for DNET"))
    } else {
        Ok(u16::from_be_bytes(*array_ref!(b, 0, 2)))
    }
}

pub fn parse_rpdu(bytes: &[u8]) -> Result<RPDU, Error> {
    if bytes.is_empty() {
        return Err(Error::Length("no rpdu data"));
    }
    // TODO: figure out if this is a single u16 or needs to be an iterator
    Ok(match bytes[0] {
        0x00 => RPDU::WhoIsRouterToNetwork(try_parse_dnet(bytes)?),
        0x01 => RPDU::IAmRouterToNetwork(try_parse_dnet(bytes)?),
        0x02 => RPDU::ICouldBeRouterToNetwork(try_parse_dnet(bytes)?),
        0x03 => RPDU::RejectMessageToNetwork,
        0x04 => RPDU::RouterBusyToNetwork,
        0x05 => RPDU::RouterAvailableToNetwork,
        0x06 => RPDU::InitializeRoutingTable,
        0x07 => RPDU::InitializeRoutingTableACK,
        0x08 => RPDU::EstablishConnectionToNetwork,
        0x09 => RPDU::DisconnectConnectionToNetwork,
        0x0A => RPDU::ChallengeRequest,
        0x0B => RPDU::SecurityPayload,
        0x0C => RPDU::SecurityResponse,
        0x0D => RPDU::RequestKeyUpdate,
        0x0E => RPDU::UpdateKeySet,
        0x0F => RPDU::UpdateDistributionKey,
        0x10 => RPDU::RequestMasterKey,
        0x11 => RPDU::SetMasterKey,
        0x12..=0x7F => RPDU::Reserved,
        0x80..=0xFF => RPDU::Proprietary,
    })
}

pub enum RPDU {
    WhoIsRouterToNetwork(DNET),
    IAmRouterToNetwork(DNET),
    ICouldBeRouterToNetwork(DNET),
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
    Reserved,
    Proprietary,
}
