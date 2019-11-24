mod bvlc;
pub use bvlc::parse_bvlc;

mod npdu;
pub use npdu::parse_npdu;

mod nsdu;

#[derive(Debug)]
pub enum Error {
    Length,
    InvalidValue,
    Unknown,
}

impl From<()> for Error {
    fn from(_: ()) -> Self {
        Self::Unknown
    }
}

#[cfg(test)]
pub mod test {
    use super::bvlc::*;

    #[test]
    fn simple_test() {
        let bytes: &[u8] = &[
            0x81, 0x0a, 0x00, 0x1b, // BVLC
            0x01, 0x20, 0x00, 0x0d, 0x01, 0x3d, 0xff, // NPDU
            0x30, 0xc9, 0x0c, 0x0c, 0x02, 0x00, 0x00, 0x6f, 0x19, 0x4c, 0x29, 0x00, 0x3e, 0x21,
            0x21, 0x3f, // APDU
        ];

        let bvlc = parse_bvlc(&bytes).unwrap();
        assert_eq!(bvlc.bvlc_function(), BVLCFunction::UnicastNPDU);

        let npdu = bvlc.npdu().as_ref().unwrap();
        assert_eq!(npdu.ncpi_control(), 0x20);
        assert_eq!(npdu.is_apdu(), true);
        assert_eq!(npdu.is_src_spec_present(), false);
        assert_eq!(npdu.is_dst_spec_present(), true);
        assert_eq!(npdu.is_expecting_reply(), false);

        assert_eq!(npdu.src().is_none(), true);

        let dst_hopcount = npdu.dst_hopcount().as_ref().unwrap();
        assert_eq!(dst_hopcount.hopcount(), 255);

        let dst = dst_hopcount.dst();
        assert_eq!(dst.net(), 13);
        assert_eq!(dst.addr().len(), 1);
        assert_eq!(dst.addr()[0], 61);
    }
}
