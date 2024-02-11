use crate::parser::common::DomainNameLabel;

use super::DNSRecordPack;


#[derive(Debug, PartialEq, Eq)]
pub struct DNSCNameRecord {
    cname: String,
}

impl DNSRecordPack for DNSCNameRecord {
    const RTYPE: u16 = 5;

    fn parse(
        data: &[u8],
        startptr: usize,
        _len: usize,
    ) -> Result<Self, String> where Self: Sized {
        let (cname, _) = DomainNameLabel::parse(data, startptr)?;

        Ok(Self { cname })
    }

    fn serialize(
        &self,
        label_ptr_map: &mut crate::parser::LabelPtrMap,
        ptr: usize,
    ) -> Result<Vec<u8>, String> {
        let (cname_bytes, mut temp_label_ptr_map) = DomainNameLabel::serialize(
            &self.cname,
            Some(&label_ptr_map),
        )?;
        temp_label_ptr_map.iter_mut().for_each(|(_, x)| *x += ptr);
        label_ptr_map.extend(temp_label_ptr_map);

        Ok(cname_bytes)
    }
}
