use crate::parser::LabelPtrMap;

use super::DNSRecordPack;

#[derive(Debug, PartialEq, Eq)]
pub struct DNSARecord { ip: [u8; 4] }

impl DNSRecordPack for DNSARecord {
    const RTYPE: u16 = 1;

    fn parse(
        data: &[u8],
        startptr: usize,
        _: usize,
    ) -> Result<Self, String> where Self: Sized {
        let ip = [
            data[startptr + 0],
            data[startptr + 1],
            data[startptr + 2],
            data[startptr + 3],
        ];

        return Ok(Self { ip })
    }

    fn serialize(
        &self,
        _label_ptr_map: &mut LabelPtrMap,
        _ptr: usize,
    ) -> Result<Vec<u8>, String> {
        Ok(self.ip.to_vec())
    }
}
