use crate::parser::{common::DomainNameLabel, LabelPtrMap};

use super::DNSRecordPack;


#[derive(Debug, PartialEq, Eq)]
pub struct DNSSOARecord {
    mname: String,
    rname: String,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
}

impl DNSRecordPack for DNSSOARecord {
    const RTYPE: usize = 6;

    fn parse(
        data: &[u8],
        startptr: usize,
        _len: usize,
    ) -> Result<Self, String> where Self: Sized {
        let mut ptr = startptr;
        let (mname, consumed_len) = DomainNameLabel::parse(data, ptr)?;
        ptr += consumed_len;
        
        let (rname, consumed_len) = DomainNameLabel::parse(data, ptr)?;
        ptr += consumed_len;

        let mut read_u32 = || {
            let value = u32::from_be_bytes([
                data[ptr + 0], data[ptr + 1], data[ptr + 2], data[ptr + 3],
            ]);
            ptr += 4;

            value
        };

        let serial = read_u32();
        let refresh = read_u32();
        let retry = read_u32();
        let expire = read_u32();
        let minimum = read_u32();

        Ok(Self {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        })
    }

    fn serialize(
        &self,
        label_ptr_map: &mut LabelPtrMap,
        ptr: usize,
    ) -> Result<Vec<u8>, String> {
        let mut data: Vec<u8> = vec![];

        let (mname_bytes, mut temp_label_ptr_map) = DomainNameLabel::serialize(
            &self.mname,
            Some(&label_ptr_map),
        )?;
        data.extend_from_slice(&mname_bytes);
        temp_label_ptr_map.iter_mut().for_each(|(_, x)| *x += ptr + data.len());
        label_ptr_map.extend(temp_label_ptr_map);

        let (rname_bytes, mut temp_label_ptr_map) = DomainNameLabel::serialize(
            &self.rname,
            Some(&label_ptr_map),
        )?;
        data.extend_from_slice(&rname_bytes);
        temp_label_ptr_map.iter_mut().for_each(|(_, x)| *x += ptr + data.len());
        label_ptr_map.extend(temp_label_ptr_map);

        data.extend_from_slice(&self.serial.to_be_bytes());
        data.extend_from_slice(&self.refresh.to_be_bytes());
        data.extend_from_slice(&self.retry.to_be_bytes());
        data.extend_from_slice(&self.expire.to_be_bytes());
        data.extend_from_slice(&self.minimum.to_be_bytes());

        Ok(data)
    }
}
