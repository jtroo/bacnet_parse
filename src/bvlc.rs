use super::npdu::*;
use super::Error;
use arrayref::array_ref;

pub fn parse_bvlc(slice: &[u8]) -> Result<BVLC, Error> {
    let mut bvlc = BVLC::default();

    if slice.len() < 4 {
        return Err(Error::Length);
    }
    if slice[0] != 0x81 {
        println!("invalid bvlc type {}", slice[0]);
        return Err(Error::InvalidValue);
    }
    let len = u16::from_be_bytes(*array_ref!(slice, 2, 2));
    if len as usize != slice.len() {
        println!("Invalid BVLC length");
        return Err(Error::Length);
    }
    bvlc.bfn = slice[1].into();
    let npdu_start_idx: usize = if bvlc.has_ip_port() {
        if slice.len() < 6 {
            return Err(Error::Length);
        }
        bvlc.ip_port = Some(array_ref!(slice, 4, 6).into());
        10
    } else {
        4
    };
    if bvlc.has_npdu() {
        if slice.len() < npdu_start_idx {
            return Err(Error::Length);
        }
        if let Ok(npdu) = parse_npdu(&slice[npdu_start_idx..]) {
            bvlc.npdu = Some(npdu);
        }
    }
    Ok(bvlc)
}

/// Note: fields are private with getters because BVLC is not intended to be constructed manually;
/// it should only be created by `parse_bvlc`.
#[derive(Default)]
pub struct BVLC<'a> {
    bfn: BVLCFunction,
    ip_port: Option<IpPort>,
    npdu: Option<NPDU<'a>>,
}

impl<'a> BVLC<'a> {
    pub fn bvlc_function(&self) -> BVLCFunction {
        self.bfn
    }
    pub fn ip_port(&self) -> &Option<IpPort> {
        &self.ip_port
    }
    pub fn npdu(&self) -> &Option<NPDU<'a>> {
        &self.npdu
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BVLCFunction {
    BVLCResult,
    WBDT,
    RBDT,
    RBDTAck,
    ForwardedNPDU,
    RegisterForeignDevice,
    UnicastNPDU,
    BroadcastNPDU,
    SecureBVLL,
    Unknown,
}

impl Default for BVLCFunction {
    fn default() -> BVLCFunction {
        Self::Unknown
    }
}

impl From<u8> for BVLCFunction {
    fn from(b: u8) -> Self {
        match b {
            0x00 => Self::BVLCResult,
            0x01 => Self::WBDT,
            0x02 => Self::RBDT,
            0x03 => Self::RBDTAck,
            0x04 => Self::ForwardedNPDU,
            0x05 => Self::RegisterForeignDevice,
            0x0a => Self::UnicastNPDU,
            0x0b => Self::BroadcastNPDU,
            0x0c => Self::SecureBVLL,
            _ => Self::Unknown,
        }
    }
}

impl BVLC<'_> {
    pub fn has_npdu(&self) -> bool {
        match &self.bfn {
            BVLCFunction::ForwardedNPDU
            | BVLCFunction::UnicastNPDU
            | BVLCFunction::BroadcastNPDU => true,
            _ => false,
        }
    }

    pub fn has_ip_port(&self) -> bool {
        match &self.bfn {
            BVLCFunction::ForwardedNPDU => true,
            _ => false,
        }
    }
}

pub struct IpPort {
    pub ip: u32,
    pub port: u16,
}

impl From<&[u8; 6]> for IpPort {
    fn from(b: &[u8; 6]) -> IpPort {
        IpPort {
            ip: u32::from_be_bytes(*array_ref!(b, 0, 4)),
            port: u16::from_be_bytes(*array_ref!(b, 4, 2)),
        }
    }
}
