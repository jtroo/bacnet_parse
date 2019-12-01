use super::npdu::*;
use super::*;
use arrayref::array_ref;
use core::convert::From;

pub fn parse_mstp_skip_crc_compute(bytes: &[u8]) -> Result<MSTPFrameNoCrcs, Error> {
    if bytes[0] != 0x55 || bytes[1] != 0xFF {
        return Err(Error::InvalidValue("not the mstp preamble"));
    }
    if bytes.len() < 8 {
        return Err(Error::Length(
            "data is shorter than minimum mstp frame size",
        ));
    }
    let mut frame = MSTPFrameNoCrcs::default();
    frame.frame_type = bytes[2].into();
    frame.dst_mac = bytes[3];
    frame.src_mac = bytes[4];
    frame.len = u16::from_be_bytes(*array_ref!(bytes, 5, 2));
    if frame.len == 0 {
        return Ok(frame);
    }
    // 10 comes from (header = 8) + (crc = 2)
    if (10 + frame.len) as usize != bytes.len() {
        // error but recoverable
        return Ok(frame);
    }
    if let Ok(npdu) = parse_npdu(&bytes[8..]) {
        frame.npdu = Some(npdu);
    }
    Ok(frame)
}

pub fn parse_mstp(bytes: &[u8]) -> Result<MSTPFrame, Error> {
    let frame = parse_mstp_skip_crc_compute(bytes)?;
    let framelen = bytes.len();

    let mut crcs = CRCs::default();
    crcs.header_actual = bytes[7];
    crcs.header_computed = compute_header_crc(*array_ref!(bytes, 2, 5));
    if framelen > 10 {
        crcs.data_actual = u16::from_le_bytes(*array_ref!(bytes, framelen - 2, 2));
        crcs.data_computed = compute_data_crc(&bytes[8..framelen - 2]);
    }

    Ok(MSTPFrame {
        frame_type: frame.frame_type,
        dst_mac: frame.dst_mac,
        src_mac: frame.src_mac,
        len: frame.len,
        npdu: frame.npdu,
        crcs,
    })
}

#[derive(Default)]
pub struct MSTPFrameNoCrcs<'a> {
    frame_type: MSTPFrameType,
    dst_mac: u8,
    src_mac: u8,
    len: u16,
    npdu: Option<NPDU<'a>>,
}

pub struct MSTPFrame<'a> {
    frame_type: MSTPFrameType,
    dst_mac: u8,
    src_mac: u8,
    len: u16,
    crcs: CRCs,
    npdu: Option<NPDU<'a>>,
}

impl<'a> MSTPFrameNoCrcs<'a> {
    pub fn frame_type(&self) -> MSTPFrameType {
        self.frame_type
    }
    pub fn dst_mac(&self) -> u8 {
        self.dst_mac
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

impl<'a> MSTPFrame<'a> {
    pub fn frame_type(&self) -> MSTPFrameType {
        self.frame_type
    }
    pub fn dst_mac(&self) -> u8 {
        self.dst_mac
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
    header_computed: u8,
    header_actual: u8,
    data_computed: u16,
    data_actual: u16,
}

impl CRCs {
    /// Returns the header CRCs: (actual value, re-computed).
    pub fn header(self) -> (u8, u8) {
        (self.header_actual, self.header_computed)
    }
    /// Returns the data CRCs: (actual value, re-computed).
    pub fn data(self) -> (u16, u16) {
        (self.data_actual, self.data_computed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MSTPFrameType {
    Token(u8),
    PollforMaster(u8),
    ReplyToPollForMaster(u8),
    TestRequest(u8),
    TestResponse(u8),
    BACnetDataExpectingReply(u8),
    BACnetDataNotExpectingReply(u8),
    ReplyPostponed(u8),
    Reserved(u8),
    Proprietary(u8),
}

impl Default for MSTPFrameType {
    fn default() -> Self {
        Self::Reserved(127)
    }
}

impl From<u8> for MSTPFrameType {
    fn from(b: u8) -> Self {
        match b {
            0 => Self::Token(b),
            1 => Self::PollforMaster(b),
            2 => Self::ReplyToPollForMaster(b),
            3 => Self::TestRequest(b),
            4 => Self::TestResponse(b),
            5 => Self::BACnetDataExpectingReply(b),
            6 => Self::BACnetDataNotExpectingReply(b),
            7 => Self::ReplyPostponed(b),
            8..=127 => Self::Reserved(b),
            128..=255 => Self::Proprietary(b),
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
            0x55, 0xff, 0x05, 0x0c, 0x7f, 0x00, 0x1f, 0x35, 0x01, 0x0c, 0x00, 0x01, 0x06, 0xc0,
            0xa8, 0x01, 0x12, 0xba, 0xc0, 0x02, 0x01, 0x6a, 0x0f, 0x0c, 0x00, 0x80, 0x00, 0x0a,
            0x19, 0x55, 0x3e, 0x44, 0x41, 0xe8, 0x00, 0x01, 0x3f, 0x49, 0x09, 0xc9, 0x6f,
        ];
        let framelen = DATA.len();
        let data_actual = u16::from_le_bytes(*array_ref!(DATA, framelen - 2, 2));
        let data_computed = compute_data_crc(&DATA[8..framelen - 2]);
        assert_eq!(data_actual, data_computed);
    }

    #[test]
    fn parse_no_crc() {
        const DATA: &[u8] = &[
            0x55, 0xff, 0x05, 0x0c, 0x7f, 0x00, 0x1f, 0x35, 0x01, 0x0c, 0x00, 0x01, 0x06, 0xc0,
            0xa8, 0x01, 0x12, 0xba, 0xc0, 0x02, 0x01, 0x6a, 0x0f, 0x0c, 0x00, 0x80, 0x00, 0x0a,
            0x19, 0x55, 0x3e, 0x44, 0x41, 0xe8, 0x00, 0x01, 0x3f, 0x49, 0x09, 0xc9, 0x6f,
        ];
        let frame = parse_mstp_skip_crc_compute(DATA).unwrap();
        assert_eq!(frame.frame_type(), MSTPFrameType::BACnetDataExpectingReply(5));
        assert_eq!(frame.dst_mac(), 12);
        assert_eq!(frame.src_mac(), 127);
        assert_eq!(frame.data_len(), 31);
        let npdu = frame.npdu().as_ref().unwrap();
        assert_eq!(npdu.ncpi_control(), 0x0c);
        assert_eq!(npdu.is_apdu(), true);
        assert_eq!(npdu.is_dst_spec_present(), false);
        assert_eq!(npdu.is_src_spec_present(), true);
        assert_eq!(npdu.is_expecting_reply(), true);
        assert_eq!(npdu.prio(), NCPIPriority::Normal);
        let src = npdu.src().as_ref().unwrap();
        assert_eq!(src.net(), 1);
        assert_eq!(src.addr().len(), 6);
        assert_eq!(src.addr()[0], 0xc0);
        assert_eq!(src.addr()[4], 0xba);
        assert_eq!(npdu.dst_hopcount().is_none(), true);
    }

    #[test]
    fn parse_crc() {
        const DATA: &[u8] = &[
            0x55, 0xff, 0x05, 0x0c, 0x7f, 0x00, 0x1f, 0x35, 0x01, 0x0c, 0x00, 0x01, 0x06, 0xc0,
            0xa8, 0x01, 0x12, 0xba, 0xc0, 0x02, 0x01, 0x6a, 0x0f, 0x0c, 0x00, 0x80, 0x00, 0x0a,
            0x19, 0x55, 0x3e, 0x44, 0x41, 0xe8, 0x00, 0x01, 0x3f, 0x49, 0x09, 0xc9, 0x6f,
        ];
        let frame = parse_mstp(DATA).unwrap();
        let (actual, computed) = frame.crcs().header();
        assert_eq!(actual, computed);
        assert_eq!(actual, 0x35);
        let (actual, computed) = frame.crcs().data();
        assert_eq!(actual, computed);
        assert_eq!(actual, 0x6fc9);
    }

    #[test]
    fn parse_crc_unequal() {
        const DATA: &[u8] = &[
            0x55, 0xff, 0x05, 0x0c, 0x7f, 0x00, 0x1f, 0x34, 0x01, 0x0c, 0x00, 0x01, 0x06, 0xc0,
            0xa8, 0x01, 0x12, 0xba, 0xc0, 0x02, 0x01, 0x6a, 0x0f, 0x0c, 0x00, 0x80, 0x00, 0x0a,
            0x19, 0x55, 0x3e, 0x44, 0x41, 0xe8, 0x00, 0x01, 0x3f, 0x49, 0x09, 0xc9, 0x6e,
        ];
        let frame = parse_mstp(DATA).unwrap();
        let (actual, computed) = frame.crcs().header();
        assert_ne!(actual, computed);
        assert_eq!(actual, 0x34);
        let (actual, computed) = frame.crcs().data();
        assert_ne!(actual, computed);
        assert_eq!(actual, 0x6ec9);
    }
}
