use crate::parser::{common::DomainNameLabel, LabelPtrMap};

use super::DNSRecordPack;


#[derive(Debug, PartialEq, Eq)]
pub struct DNSNSRecord {
    pub nsdname: String,
}

impl DNSRecordPack for DNSNSRecord {
    const RTYPE: u16 = 2;

    fn parse(
        data: &[u8],
        startptr: usize,
        _: usize,
    ) -> Result<Self, String> where Self: Sized {
        let (name, _) = DomainNameLabel::parse(data, startptr)?;

        Ok(Self { nsdname: name })
    }

    fn serialize(
        &self,
        label_ptr_map: &mut LabelPtrMap,
        ptr: usize,
    ) -> Result<Vec<u8>, String> {
        let (bytes, mut nsdname_label_ptr_map) = DomainNameLabel::serialize(
            &self.nsdname,
            Some(label_ptr_map)
        )?;

        nsdname_label_ptr_map.iter_mut().for_each(|(_, x)| *x += ptr);
        label_ptr_map.extend(nsdname_label_ptr_map);
        
        Ok(bytes)
    }
}
