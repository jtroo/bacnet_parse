use super::npdu::*;
use super::*;
use arrayref::array_ref;
use std::convert::From;

pub fn parse_mstp_skip_crc_checks(bytes: &[u8]) -> Result<MstpFrameNoCrcs, Error> {
    if bytes.len() < 8 {
        println!("mstp len err");
        return Err(Error::Length);
    }
    Err(Error::Unknown)
}

pub fn parse_mstp(bytes: &[u8]) -> Result<MstpFrame, Error> {
    let frame = parse_mstp_skip_crc_checks(bytes)?;
    let framelen = bytes.len();
    let mut crcs = CRCs::default();
    crcs.header_actual = bytes[7];
    crcs.header_expected = compute_header_crc(*array_ref!(bytes, 2, 5));
    if framelen > 10 {
        crcs.data_actual = u16::from_le_bytes(*array_ref!(bytes, framelen - 2, 2));
        crcs.data_expected = compute_data_crc(&bytes[8..framelen-2]);
    }
    Err(Error::Unknown)
}

pub struct MstpFrameNoCrcs<'a> {
    frame_type: u8,
    dest_mac: u8,
    src_mac: u8,
    len: u16,
    npdu: Option<NPDU<'a>>,
}

pub struct MstpFrame<'a> {
    frame_type: u8,
    dest_mac: u8,
    src_mac: u8,
    len: u16,
    crcs: CRCs,
    npdu: Option<NPDU<'a>>,
}

impl<'a> MstpFrameNoCrcs<'a> {
    pub fn frame_type(&self) -> u8 {
        self.frame_type
    }
    pub fn dest_mac(&self) -> u8 {
        self.dest_mac
    }
    pub fn src_mac(&self) -> u8 {
        self.src_mac
    }
    pub fn data_len(&self) -> u16 {
        self.len
    }
    pub fn npdu(&self) -> &Option<NPDU<'a>> {
        &self.npdu
    }
}

impl<'a> MstpFrame<'a> {
    pub fn frame_type(&self) -> u8 {
        self.frame_type
    }
    pub fn dest_mac(&self) -> u8 {
        self.dest_mac
    }
    pub fn src_mac(&self) -> u8 {
        self.src_mac
    }
    pub fn data_len(&self) -> u16 {
        self.len
    }
    pub fn crcs(&self) -> CRCs {
        self.crcs
    }
    pub fn npdu(&self) -> &Option<NPDU<'a>> {
        &self.npdu
    }
}

#[derive(Clone, Copy, Default)]
pub struct CRCs {
    header_expected: u8,
    header_actual: u8,
    data_expected: u16,
    data_actual: u16,
}

impl CRCs {
    pub fn header(self) -> (u8, u8) {
        (self.header_actual, self.header_expected)
    }
    pub fn data(self) -> (u16, u16) {
        (self.data_actual, self.data_expected)
    }
}

enum FrameType {
    Token,
    PollforMaster,
    ReplyToPollForMaster,
    TestRequest,
    TestResponse,
    BACnetDataExpectingReply,
    BACnetDataNotExpectingReply,
    ReplyPostponed,
    Reserved,
    Proprietary,
}

impl From<u8> for FrameType {
    fn from(b: u8) -> Self {
        match b {
            0 => Self::Token,
            1 => Self::PollforMaster,
            2 => Self::ReplyToPollForMaster,
            3 => Self::TestRequest,
            4 => Self::TestResponse,
            5 => Self::BACnetDataExpectingReply,
            6 => Self::BACnetDataNotExpectingReply,
            7 => Self::ReplyPostponed,
            8..=127 => Self::Reserved,
            128..=255 => Self::Proprietary,
        }
    }
}

/// The 5 input bytes are the frame type, destination, source, and 2xlength bytes.
fn compute_header_crc(bytes: [u8; 5]) -> u8 {
    // algorithm translated from BACnet standard
    let mut crc: u16 = 0xFF;
    for b in &bytes {
        crc ^= u16::from(*b);
        crc ^= (crc << 1)
            ^ (crc << 2)
            ^ (crc << 3)
            ^ (crc << 4)
            ^ (crc << 5)
            ^ (crc << 6)
            ^ (crc << 7);
        crc = (crc & 0xFE) ^ ((crc >> 8) & 1);
    }
    !crc as u8
}

/// The data should be everything in between the header crc and data crc.
fn compute_data_crc(bytes: &[u8]) -> u16 {
    // algorithm translated from BACnet standard
    let mut crc: u16 = 0xFFFF;
    for b in bytes {
        let low = (crc & 0xff) ^ u16::from(*b);
        crc = (crc >> 8)
            ^ (low << 8)
            ^ (low << 3)
            ^ (low << 12)
            ^ (low >> 4)
            ^ (low & 0xf)
            ^ ((low & 0x0f) << 7);
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_crc_test() {
        const HEADER: &[u8] = &[0x55, 0xff, 0x06, 0x7f, 0x02, 0x00, 0x1d, 0x90];
        assert_eq!(compute_header_crc(*array_ref!(HEADER, 2, 5)), 0x90);
    }

    #[test]
    fn data_crc_test() {
        const DATA: &[u8] = &[
            0x01, 0x20, 0x00, 0x01, 0x06, 0xc0, 0xa8, 0x01, 0x0a, 0xba, 0xc0, 0xff, // NPDU
            0x30, 0xbd, 0x0c, 0x0c, 0x00, 0x80, 0x00, 0x0e, 0x19, 0x55, 0x3e, 0x44, 0x3e, 0xce,
            0x72, 0xad, 0x3f, // APDU
        ];
        assert_eq!(compute_data_crc(DATA), 0xade7);
    }

    #[test]
    fn data_crc_test2() {
        const DATA: &[u8] = &[
            0x55,0xff,0x05,0x0c,0x7f,0x00,0x1f,0x35,0x01,0x0c,0x00,0x01,0x06,0xc0,0xa8,0x01
                ,0x12,0xba,0xc0,0x02,0x01,0x6a,0x0f,0x0c,0x00,0x80,0x00,0x0a,0x19,0x55,0x3e,0x44
                ,0x41,0xe8,0x00,0x01,0x3f,0x49,0x09,0xc9,0x6f
        ];
        let framelen = DATA.len();
        let data_actual = u16::from_le_bytes(*array_ref!(DATA, framelen - 2, 2));
        let data_expected = compute_data_crc(&DATA[8..framelen-2]);
        assert_eq!(data_actual, data_expected);
    }
}