use std::collections::HashMap;

use super::{common::{ParseResult, DomainNameLabel}, LabelPtrMap};

mod a_record;
mod ns_record;
mod cname_record;
mod soa_record;
mod mx_record;
mod txt_record;
mod aaaa_record;
mod unknown_record;

pub use a_record::DNSARecord;
pub use ns_record::DNSNSRecord;
pub use cname_record::DNSCNameRecord;
pub use soa_record::DNSSOARecord;
pub use mx_record::DNSMXRecord;
pub use txt_record::DNSTXTRecord;
pub use aaaa_record::DNSAAAARecord;
pub use unknown_record::DNSUnknownRecord;

pub trait DNSRecordPack {
    const RTYPE: u16;

    fn parse(
        data: &[u8],
        startptr: usize,
        len: usize,
    ) -> Result<Self, String> where Self: Sized;

    fn serialize(
        &self,
        label_ptr_map: &mut LabelPtrMap,
        ptr: usize,
    ) -> Result<Vec<u8>, String>;
}


#[derive(Debug, PartialEq, Eq)]
pub struct DNSRecord {
    /// Domain name
    pub name: String,

    /// Record type (16 bit)
    pub rtype: u16,

    /// Class (16 bit)
    pub class: u16,

    /// TTL (32 bit)
    pub ttl: u32,

    /// Length of the data (16 bit)
    pub len: u16,

    /// Record data (variable)
    pub record: DNSRecordData,
}

pub struct DNSRecordsParser<'data> {
    packet: &'data [u8],
}

impl<'data> DNSRecordsParser<'data> {
    pub fn new(packet: &'data [u8]) -> Self {
        Self { packet }
    }

    pub fn parse(&self, num_records: usize, startptr: usize) -> ParseResult<Vec<DNSRecord>> {
        let mut ptr = startptr;
        let mut result = vec![];
        
        for _ in 0..num_records {
            let (answer, len) = self.parse_record(ptr)?;

            result.push(answer);

            ptr += len;
        }

        Ok((result, ptr - startptr))
    }

    fn parse_record(&self, ptr: usize) -> ParseResult<DNSRecord> {
        let (name, consumed_len) = DomainNameLabel::parse(self.packet, ptr)?;
        let end = ptr + consumed_len;

        let rtype = u16::from_be_bytes([self.packet[end + 0], self.packet[end + 1]]);
        let class = u16::from_be_bytes([self.packet[end + 2], self.packet[end + 3]]);
        let ttl = u32::from_be_bytes([
            self.packet[end + 4],
            self.packet[end + 5],
            self.packet[end + 6],
            self.packet[end + 7],
        ]);

        let len = u16::from_be_bytes([
            self.packet[end + 8],
            self.packet[end + 9],
        ]);

        let (record, record_len) = self.parse_record_data(
            rtype,
            len as usize,
            end + 10,
        )?;

        Ok((
            DNSRecord {
                name,
                rtype,
                class,
                ttl,
                len,
                record,
            },
            consumed_len + 2 + 2 + 4 + 2 + record_len
        ))
    }

    fn parse_record_data(
        &self,
        rtype: u16,
        len: usize,
        ptr: usize,
    ) -> ParseResult<DNSRecordData> {

        // TODO: Find a way to refactor this
        match rtype {
            DNSARecord::RTYPE => {
                let record_data = DNSRecordData::A(
                    DNSARecord::parse(&self.packet, ptr, len)?
                );
                return Ok((record_data, len))
            },
            DNSNSRecord::RTYPE => {
                let record_data = DNSRecordData::NS(
                    DNSNSRecord::parse(&self.packet, ptr, len)?
                );
                return Ok((record_data, len))
            },
            DNSCNameRecord::RTYPE => {
                let record_data = DNSRecordData::CNAME(
                    DNSCNameRecord::parse(&self.packet, ptr, len)?
                );
                return Ok((record_data, len))
            },
            DNSSOARecord::RTYPE => {
                let record_data = DNSRecordData::SOA(
                    DNSSOARecord::parse(self.packet, ptr, len)?
                );

                Ok((record_data, len))
            },
            DNSMXRecord::RTYPE => {
                let record_data = DNSRecordData::MX(
                    DNSMXRecord::parse(self.packet, ptr, len)?
                );

                Ok((record_data, len))
            },
            DNSTXTRecord::RTYPE => {
                let record_data = DNSRecordData::TXT(
                    DNSTXTRecord::parse(self.packet, ptr, len)?
                );

                Ok((record_data, len))
            },
            DNSAAAARecord::RTYPE => {
                let record_data = DNSRecordData::AAAA(
                    DNSAAAARecord::parse(self.packet, ptr, len)?
                );

                Ok((record_data, len))
            },
            _ => {
                Ok((
                    DNSRecordData::Unknown(
                        DNSUnknownRecord::parse(&self.packet, ptr, len)?
                    ),
                    len
                ))
            },
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum DNSRecordData {
    A(DNSARecord),
    NS(DNSNSRecord),
    CNAME(DNSCNameRecord),
    SOA(DNSSOARecord),
    MX(DNSMXRecord),
    TXT(DNSTXTRecord),
    AAAA(DNSAAAARecord),
    Unknown(DNSUnknownRecord),
}

impl DNSRecordData {
    fn serialize(&self) -> Vec<u8> {
        /*
        let record: impl DNSRecordPack = self.into();

        match self {
            Self::A(record) => record.serialize(),
            Self::NS(record) => record.serialize(),
            Self::Unknown(record) => record.serialize(),
            Self::SOA(record) => record.serialize(),
        }
        */

        vec![]
    }
}

pub struct DNSRecordSerializer<'data, 'lmap> {
    records: &'data [DNSRecord],
    label_ptr_map: &'lmap mut LabelPtrMap,
    ptr: usize,
}

impl<'data, 'lmap> DNSRecordSerializer<'data, 'lmap> {
    pub fn new(
        records: &'data [DNSRecord],
        label_ptr_map: &'lmap mut HashMap<String, usize>,
        ptr: usize,
    ) -> Self {
        Self { records, label_ptr_map, ptr }
    }

    pub fn serialize(&mut self) -> Result<Vec<u8>, String> {
        let mut ptr = 0;
        let mut data = Vec::new();

        for record in self.records {
            let (name, mut label_ptr_map) = DomainNameLabel::serialize(
                &record.name,
                Some(self.label_ptr_map),
            )?;

            label_ptr_map.iter_mut().for_each(|(_, x)| *x += ptr + self.ptr);
            self.label_ptr_map.extend(label_ptr_map);

            data.extend_from_slice(&name);
            data.extend_from_slice(&record.rtype.to_be_bytes());
            data.extend_from_slice(&record.class.to_be_bytes());
            data.extend_from_slice(&record.ttl.to_be_bytes());
            data.extend_from_slice(&record.len.to_be_bytes());
            data.extend_from_slice(&record.record.serialize());

            ptr += name.len() + 2 + 2 + 4 + 2 + record.len as usize;
        }

        Ok(data)
    }
}
