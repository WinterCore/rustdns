use crate::parser::LabelPtrMap;

use super::DNSRecordPack;


#[derive(Debug, PartialEq, Eq)]
pub struct DNSAAAARecord {
    // TODO: I'm not sure what's the most efficient way to store ipv6 addresses
    ip: [u8; 16],
}

impl DNSRecordPack for DNSAAAARecord {
    const RTYPE: u16 = 28;

    fn parse(
        data: &[u8],
        startptr: usize,
        _: usize,
    ) -> Result<Self, String> where Self: Sized {
        
        Ok(Self {
            ip: data[startptr..(startptr + 16)]
                .try_into()
                .map_err(|_| "Failed to parse AAAA record".to_owned())?,
        })
    }

    fn serialize(
        &self,
        _label_ptr_map: &mut LabelPtrMap,
        _ptr: usize,
    ) -> Result<Vec<u8>, String> {
        Ok(self.ip.to_vec())
    }
}
