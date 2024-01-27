use super::common::{ParseResult, read_qname};


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
        let (name, consumed_len) = read_qname(self.packet, ptr)?;
        let end = ptr + consumed_len;

        let rtype = u16::from_le_bytes([self.packet[end + 1], self.packet[end + 0]]);
        let class = u16::from_le_bytes([self.packet[end + 3], self.packet[end + 2]]);
        let ttl = u32::from_le_bytes([
            self.packet[end + 7],
            self.packet[end + 6],
            self.packet[end + 5],
            self.packet[end + 4],
        ]);

        let len = u16::from_le_bytes([
            self.packet[end + 9],
            self.packet[end + 8],
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
                    let ip = [
                        self.packet[ptr + 0],
                        self.packet[ptr + 1],
                        self.packet[ptr + 2],
                        self.packet[ptr + 3],
                    ];

                    return Ok((DNSRecordData::A { ip }, 4))
                }

                Err(format!("DNSRecordsParser: invalid A record length {}", len))
            },
            _ => {
                Ok((DNSRecordData::Unknown { data: self.packet[ptr..(ptr + len)].to_owned() }, len))
            },
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum DNSRecordData {
    A {
        ip: [u8; 4],
    },
    Unknown {
        data: Vec<u8>,
    },
}
