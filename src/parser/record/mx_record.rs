use crate::parser::common::DomainNameLabel;

use super::DNSRecordPack;


#[derive(Debug, PartialEq, Eq)]
pub struct DNSMXRecord {
    preference: u16,
    exchange: String
}

impl DNSRecordPack for DNSMXRecord {
    const RTYPE: u16 = 15;

    fn parse(
        data: &[u8],
        startptr: usize,
        _len: usize,
    ) -> Result<Self, String> where Self: Sized {
        println!("MXLEN: {:?}", _len);
        let preference = u16::from_be_bytes([data[startptr + 0], data[startptr + 1]]);
        let (exchange, _) = DomainNameLabel::parse(data, startptr + 2)?;


        Ok(Self {
            preference,
            exchange,
        })
    }

    fn serialize(
        &self,
        label_ptr_map: &mut crate::parser::LabelPtrMap,
        ptr: usize,
    ) -> Result<Vec<u8>, String> {
        let mut data: Vec<u8> = vec![];

        data.extend_from_slice(&self.preference.to_be_bytes());

        let (exchange_bytes, mut temp_label_ptr_map) = DomainNameLabel::serialize(
            &self.exchange,
            Some(label_ptr_map),
        )?;

        temp_label_ptr_map.iter_mut().for_each(|(_, x)| *x += ptr + data.len());
        label_ptr_map.extend(temp_label_ptr_map);
        data.extend_from_slice(&exchange_bytes);

        Ok(data)
    }
}
