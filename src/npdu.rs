use super::Error;
use arrayref::array_ref;

pub fn parse_npdu(bytes: &[u8]) -> Result<NPDU, Error> {
    if bytes.len() < 3 {
        return Err(Error::Length("insufficient size for npdu"));
    }
    if bytes[0] != 0x01 {
        return Err(Error::InvalidValue("unhandled npdu version"));
    }

    let mut npdu = NPDU::default();
    npdu.ncpi_control = bytes[1];

    npdu.payload = if npdu.is_dst_spec_present() {
        let bytes_after_dst = if let Ok((s, dst)) = NetAddr::parse(&bytes[2..]) {
            npdu.dst = Some(DstHopCount { dst, hopcount: 0 });
            s
        } else {
            bytes
        };

        let hopcount_bytes = if npdu.is_src_spec_present() {
            let (bytes_after_src, src) = NetAddr::parse(bytes_after_dst)?;
            npdu.src = Some(src);
            bytes_after_src
        } else {
            bytes_after_dst
        };

        if hopcount_bytes.len() < 2 {
            return Err(Error::Length("insufficient size for hopcount and payload"));
        }
        if let Some(dst_hopcount) = &mut npdu.dst {
            dst_hopcount.hopcount = hopcount_bytes[0];
            &hopcount_bytes[1..]
        } else {
            hopcount_bytes
        }
    } else if npdu.is_src_spec_present() {
        let (bytes_after_src, src_addr) = NetAddr::parse(&bytes[2..])?;
        npdu.src = Some(src_addr);
        bytes_after_src
    } else {
        &bytes[2..]
    };
    Ok(npdu)
}

#[derive(Default)]
pub struct NPDU<'a> {
    ncpi_control: u8,
    dst: Option<DstHopCount<'a>>,
    src: Option<NetAddr<'a>>,
    payload: &'a [u8],
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
            _ => unsafe { core::hint::unreachable_unchecked() },
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

    pub fn payload(&self) -> &'a [u8] {
        self.payload
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
            return Err(Error::Length("insufficient size for netaddr"));
        }
        let net = u16::from_be_bytes(*array_ref!(b, 0, 2));
        let addrlen = b[2];
        let rest_of_bytes_offset = 3 + addrlen as usize;
        if b.len() < rest_of_bytes_offset {
            return Err(Error::Length("insufficient size for netaddr address"));
        }
        let addr = &b[3..3 + addrlen as usize];
        Ok((&b[rest_of_bytes_offset..], Self { net, addr }))
    }

    pub fn net(&self) -> u16 {
        self.net
    }

    pub fn addr(&self) -> &'a [u8] {
        self.addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netaddr_test() {
        const BYTES: &[u8] = &[0x12, 0x34, 0x4, 192, 168, 1, 10];
        let (rest, netaddr) = NetAddr::parse(BYTES).unwrap();
        assert_eq!(rest.len(), 0);
        assert_eq!(netaddr.net(), 0x1234);
        assert_eq!(netaddr.addr(), &[192, 168, 1, 10]);
    }
}
