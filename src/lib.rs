//! [![LICENSE](https://img.shields.io/badge/license-MPL_2.0-blue.svg)](LICENSE)
//! [![Crates.io Version](https://img.shields.io/crates/v/bacnet_parse.svg)](https://crates.io/crates/bacnet_parse)
//!
//! # bacnet_parse is a #![no_std] library to parse BACnet bytes into read-only data structures
//!
//! Currently handles:
//! * MS/TP
//! * BVLL (basic - just enough to get NPDU)
//! * NPDU
//!
//! Targeting support for:
//! * NSDU ([NLM/RPDU](http://www.bacnetwiki.com/wiki/index.php?title=Network_Layer_Message_Type), APDU)
//!
//! To assist parsing BACnet IP or BACnet Ethernet, two recommended libraries are:
//! * [pnet](https://crates.io/crates/pnet)
//! * [etherparse](https://crates.io/crates/etherparse)
//!
//! ## How to use this library
//!
//! For BACnet ethernet and BACnet IP, first identify your BACnet application layer bytes then call
//! to `parse_bvlc(bytes)` and go from there.
//!
//! For MSTP, call either `parse_mstp(bytes)` or `parse_mstp_skip_crc_compute(bytes)`.
//!
//! Not yet implemented below:
//!
//! In order to parse the RPDU or APDU, first check which one you have with `npdu.is_apdu()` then
//! call either `parse_apdu(npdu.payload())` or `parse_rpdu(npdu.payload())`.
//!
//! ## Examples
//!
//! BVLC example
//!
//! ```
//! # use bacnet_parse::*;
//! # use bacnet_parse::bvlc::*;
//! # fn main() -> Result <(), Error> {
//! let bytes: &[u8] = &[
//!     0x81, 0x0a, 0x00, 0x1b, // BVLC
//!     0x01, 0x20, 0x00, 0x0d, 0x01, 0x3d, 0xff, // NPDU
//!     0x30, 0xc9, 0x0c, 0x0c, 0x02, 0x00, 0x00, 0x6f, 0x19, 0x4c, 0x29, 0x00, 0x3e, 0x21,
//!     0x21, 0x3f, // APDU
//! ];
//!
//! let bvlc = parse_bvlc(&bytes)?;
//!
//! assert_eq!(bvlc.bvlc_function(), BVLCFunction::UnicastNPDU);
//!
//! let npdu = bvlc.npdu().as_ref().expect("npdu");
//!
//! assert_eq!(npdu.ncpi_control(), 0x20);
//! assert_eq!(npdu.is_apdu(), true);
//! assert_eq!(npdu.is_src_spec_present(), false);
//! assert_eq!(npdu.is_dst_spec_present(), true);
//! assert_eq!(npdu.is_expecting_reply(), false);
//! assert_eq!(npdu.src().is_none(), true);
//!
//! let dst_hopcount = npdu.dst_hopcount().as_ref().expect("dst_hopcount");
//!
//! assert_eq!(dst_hopcount.hopcount(), 255);
//!
//! let dst = dst_hopcount.dst();
//!
//! assert_eq!(dst.net(), 13);
//! assert_eq!(dst.addr().len(), 1);
//! assert_eq!(dst.addr()[0], 61);
//! # Ok(())
//! # }
//! ```
//!
//! MSTP example
//! ```
//! # use bacnet_parse::*;
//! # use bacnet_parse::mstp::*;
//! # fn main() -> Result <(), Error> {
//! let bytes: &[u8] = &[
//!     0x55, 0xff, 0x05, 0x0c, 0x7f, 0x00, 0x1f, 0x35, 0x01, 0x0c, 0x00, 0x01, 0x06, 0xc0,
//!     0xa8, 0x01, 0x12, 0xba, 0xc0, 0x02, 0x01, 0x6a, 0x0f, 0x0c, 0x00, 0x80, 0x00, 0x0a,
//!     0x19, 0x55, 0x3e, 0x44, 0x41, 0xe8, 0x00, 0x01, 0x3f, 0x49, 0x09, 0xc9, 0x6f,
//! ];
//!
//! let frame = parse_mstp(bytes)?;
//!
//! let (actual, expected) = frame.crcs().header();
//! assert_eq!(actual, expected);
//! assert_eq!(actual, 0x35);
//!
//! let (actual, expected) = frame.crcs().data();
//! assert_eq!(actual, expected);
//! assert_eq!(actual, 0x6fc9);
//!
//! assert_eq!(frame.frame_type(), MSTPFrameType::BACnetDataExpectingReply(5));
//! let npdu = frame.npdu().as_ref().expect("npdu");
//!
//! let src = npdu.src().as_ref().expect("src");
//! assert_eq!(src.net(), 1);
//! assert_eq!(src.addr().len(), 6);
//! let addr_cmp: &[u8] = &[0xc0, 0xa8, 0x01, 0x12, 0xba, 0xc0];
//! assert_eq!(src.addr(), addr_cmp);
//! assert_eq!(npdu.dst_hopcount().is_none(), true);
//!
//! let bytes: &[u8] = &[
//!     0x55, 0xff, 0x05, 0x0c, 0x7f, 0x00, 0x1f, 0x34, 0x01, 0x0c, 0x00, 0x01, 0x06, 0xc0,
//!     0xa8, 0x01, 0x12, 0xba, 0xc0, 0x02, 0x01, 0x6a, 0x0f, 0x0c, 0x00, 0x80, 0x00, 0x0a,
//!     0x19, 0x55, 0x3e, 0x44, 0x41, 0xe8, 0x00, 0x01, 0x3f, 0x49, 0x09, 0xc9, 0x6e,
//! ];
//!
//! let frame = parse_mstp(bytes)?;
//!
//! let (actual, expected) = frame.crcs().header();
//! assert_ne!(actual, expected);
//! assert_eq!(actual, 0x34);
//!
//! let (actual, expected) = frame.crcs().data();
//! assert_ne!(actual, expected);
//! assert_eq!(actual, 0x6ec9);
//! # Ok(())
//! # }
//! ```
//!
//! ## Why not use [nom](https://crates.io/crates/nom)?
//!
//! nom is a great library, but I don't think it's well suited to application layer data with weird
//! formats like BACnet. For example, the weirdness of the NPDU layout where the hop count value's
//! existence is tied to but may or may not be contiguous with the destination port/address.
//!
//! Avoiding the use of nom may also lower the barrier to entry for contribution so that a
//! potential contributor does not also need to learn the nom library.
//!
//! These are opinions, so if you disagree and would like to use nom for parsing, feel free to make
//! a pull request that includes nom.
#![no_std]

pub mod mstp;
pub use mstp::{parse_mstp, parse_mstp_skip_crc_compute};

pub mod bvlc;
pub use bvlc::parse_bvlc;

pub mod npdu;

pub mod nsdu;
pub use nsdu::{parse_apdu, parse_rpdu};

#[derive(Debug)]
pub enum Error {
    Length(&'static str),
    InvalidValue(&'static str),
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
