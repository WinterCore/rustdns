use std::collections::HashMap;

use super::{common::{ParseResult, DomainNameLabel}, LabelPtrMap};


#[derive(Debug, PartialEq)]
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
        match rtype {
            1 => {
                if len == 4 {
                    let record_data = DNSRecordData::A(DNSARecord::parse(&self.packet[ptr..(ptr + 4)])?);
                    return Ok((record_data, 4))
                }

                // TODO: Move into record parsers
                Err(format!("DNSRecordsParser: invalid A record length {}", len))
            },
            _ => {
                Ok((DNSRecordData::Unknown { data: self.packet[ptr..(ptr + len)].to_owned() }, len))
            },
        }
    }
}

#[derive(Debug, PartialEq)]
struct DNSARecord { ip: [u8; 4] }

impl DNSARecord {
    fn parse(data: &[u8]) -> Result<Self, String> {
        let ip = [data[0], data[1], data[2], data[3]];

        return Ok(Self { ip })
    }
}

#[derive(Debug, PartialEq)]
pub enum DNSRecordData {
    A(DNSARecord),
    Unknown {
        data: Vec<u8>,
    },
}

pub struct DNSRecordSerializer<'data, 'lmap> {
    records: &'data [DNSRecord],
    label_ptr_map: &'lmap LabelPtrMap,
}

impl<'data, 'lmap> DNSRecordSerializer<'data, 'lmap> {
    pub fn new(
        records: &'data [DNSRecord],
        label_ptr_map: &'lmap HashMap<String, usize>,
    ) -> Self {
        Self { records, label_ptr_map }
    }

    pub fn serialize(&self) -> Result<(Vec<u8>, LabelPtrMap), String> {
        let mut ptr = 0;
        let mut ptr_map = HashMap::new();
        let mut data = Vec::new();

        for record in self.records {
            // Serialize the name
        }

        Ok((data, ptr_map))
    }
}
