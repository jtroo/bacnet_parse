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
//! ## Example
//!
//! ```
//! # use bacnet_parse::*;
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
//! let npdu = match bvlc.npdu() {
//!     Some(n) => n,
//!     None => panic!("npdu should be Some")
//! };
//!
//! assert_eq!(npdu.ncpi_control(), 0x20);
//! assert_eq!(npdu.is_apdu(), true);
//! assert_eq!(npdu.is_src_spec_present(), false);
//! assert_eq!(npdu.is_dst_spec_present(), true);
//! assert_eq!(npdu.is_expecting_reply(), false);
//! assert_eq!(npdu.src().is_none(), true);
//!
//! let dst_hopcount = match npdu.dst_hopcount() {
//!     Some(dh) => dh,
//!     None => panic!("dst_hopcount should be Some")
//! };
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

mod mstp;
pub use mstp::*;

mod bvlc;
pub use bvlc::*;

mod npdu;
pub use npdu::*;

mod nsdu;
pub use nsdu::*;

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
