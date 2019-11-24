use super::nsdu::*;
use super::Error;
use arrayref::array_ref;

pub fn parse_npdu(slice: &[u8]) -> Result<NPDU, Error> {
    if slice.len() < 3 {
        println!("npdu len too short");
        return Err(Error::Length);
    }
    if slice[0] != 0x01 {
        println!("unhandled npdu version {}", slice[0]);
        return Err(Error::InvalidValue);
    }

    let mut npdu = NPDU::default();
    npdu.ncpi_control = slice[1];

    let _nsdu_start = if npdu.is_dst_spec_present() {
        let slice_after_dst = if let Ok((s, dst)) = NetAddr::parse(&slice[2..]) {
            npdu.dst = Some(DstHopCount { dst, hopcount: 0 });
            s
        } else {
            slice
        };

        let hopcount_slice = if npdu.is_src_spec_present() {
            let (slice_after_src, src) = NetAddr::parse(slice_after_dst)?;
            npdu.src = Some(src);
            slice_after_src
        } else {
            slice_after_dst
        };

        if let Some(dst_hopcount) = &mut npdu.dst {
            dst_hopcount.hopcount = hopcount_slice[0];
            &hopcount_slice[1..]
        } else {
            hopcount_slice
        }
    } else if npdu.is_src_spec_present() {
        let (slice_after_src, src_addr) = NetAddr::parse(&slice[2..])?;
        npdu.src = Some(src_addr);
        slice_after_src
    } else {
        &slice[2..]
    };

    // TODO: parse nsdu
    Ok(npdu)
}

#[derive(Default)]
pub struct NPDU<'a> {
    ncpi_control: u8,
    dst: Option<DstHopCount<'a>>,
    src: Option<NetAddr<'a>>,
    nsdu: NSDU<'a>,
}

impl<'a> NPDU<'a> {
    pub fn is_apdu(&self) -> bool {
        self.ncpi_control & 0x80 == 0
    }

    pub fn is_dst_spec_present(&self) -> bool {
        self.ncpi_control & 0x20 != 0
    }

    pub fn is_src_spec_present(&self) -> bool {
        self.ncpi_control & 0x08 != 0
    }

    pub fn is_expecting_reply(&self) -> bool {
        self.ncpi_control & 0x04 != 0
    }

    pub fn prio(&self) -> NCPIPriority {
        match self.ncpi_control & 3 {
            0 => NCPIPriority::Normal,
            1 => NCPIPriority::Urgent,
            2 => NCPIPriority::CriticalEquip,
            3 => NCPIPriority::LifeSafety,
            _ => unsafe { std::hint::unreachable_unchecked() },
        }
    }

    pub fn src(&self) -> &Option<NetAddr<'a>> {
        &self.src
    }

    pub fn dst_hopcount(&self) -> &Option<DstHopCount<'a>> {
        &self.dst
    }

    pub fn ncpi_control(&self) -> u8 {
        self.ncpi_control
    }

    pub fn nsdu(&self) -> &NSDU<'a> {
        &self.nsdu
    }
}

#[derive(Debug, PartialEq)]
pub enum NCPIPriority {
    LifeSafety,
    CriticalEquip,
    Urgent,
    Normal,
}

#[derive(Default)]
pub struct DstHopCount<'a> {
    dst: NetAddr<'a>,
    hopcount: u8,
}

impl<'a> DstHopCount<'a> {
    pub fn dst(&self) -> &NetAddr<'a> {
        &self.dst
    }

    pub fn hopcount(&self) -> u8 {
        self.hopcount
    }
}

#[derive(Default, Debug)]
pub struct NetAddr<'a> {
    net: u16,
    addr: &'a [u8],
}

impl<'a> NetAddr<'a> {
    fn parse(b: &'a [u8]) -> Result<(&'a [u8], Self), Error> {
        if b.len() < 4 {
            println!("dsthopcount len err");
            return Err(Error::Length);
        }
        let net = u16::from_be_bytes(*array_ref!(b, 0, 2));
        let addrlen = b[2];
        let rest_of_slice_offset = 3 + addrlen as usize;
        if b.len() < rest_of_slice_offset {
            println!("dsthopcount len err 2");
            return Err(Error::Length);
        }
        let addr = &b[3..3 + addrlen as usize];
        Ok((&b[rest_of_slice_offset..], Self { net, addr }))
    }

    pub fn net(&self) -> u16 {
        self.net
    }

    pub fn addr(&self) -> &'a [u8] {
        self.addr
    }
}
