use crate::parser::LabelPtrMap;

use super::DNSRecordPack;

#[derive(Debug, PartialEq, Eq)]
pub struct DNSUnknownRecord {
    data: Vec<u8>,
}

impl DNSRecordPack for DNSUnknownRecord {
    const RTYPE: usize = 0;

    fn parse(
        data: &[u8],
        startptr: usize,
        len: usize,
    ) -> Result<Self, String> where Self: Sized {
        return Ok(Self {
            data: data[startptr..(startptr + len)].to_vec(),
        })
    }

    fn serialize(
        &self,
        _label_ptr_map: &mut LabelPtrMap,
        _ptr: usize,
    ) -> Result<Vec<u8>, String> {
        Ok(self.data.clone())
    }
}
