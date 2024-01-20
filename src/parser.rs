use std::collections::VecDeque;


type ParseResult<T> = Result<(
    T,     // Parsed object
    usize, // Consumed length
), String>;

pub trait Parse: Sized {
    // -> (Self, Bytes consumed)
    fn parse(data: &[u8]) -> ParseResult<Self>;
}

#[derive(Debug, PartialEq)]
enum DNSHeaderType {
    Query,
    Response,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum ResultCode {
    /// No error condition
    NoError = 0,

    /// Format error - The name server was
    /// unable to interpret the query.
    FormatError = 1,

    /// Server failure - The name server was
    /// unable to process this query due to a
    /// problem with the name server.
    ServerFailure = 2,


    /// Name Error - Meaningful only for
    /// responses from an authoritative name
    /// server, this code signifies that the
    /// domain name referenced in the query does
    /// not exist.
    NameError = 3,

    /// Not Implemented - The name server does
    /// not support the requested kind of query.
    NotImplemented = 4,


    /// Refused - The name server refuses to
    /// perform the specified operation for
    /// policy reasons.  For example, a name
    /// server may not wish to provide the
    /// information to the particular requester,
    /// or a name server may not wish to perform
    /// a particular operation (e.g., zone transfer)
    /// for particular data
    Refused = 5,


    /// Codes between 6 and 15 are reserved
    Unknown = 6,
}

impl Into<usize> for ResultCode {
    fn into(self) -> usize {
        match self {
            Self::NoError => 0,
            Self::FormatError => 1,
            Self::ServerFailure => 2,
            Self::NameError => 3,
            Self::NotImplemented => 4,
            Self::Refused => 5,
            _ => 0,
        }
    }
}

impl From<usize> for ResultCode {
    fn from(value: usize) -> Self {
        match value {
            0 => Self::NoError,
            1 => Self::FormatError,
            2 => Self::ServerFailure,
            3 => Self::NameError,
            4 => Self::NotImplemented,
            5 => Self::Refused,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, PartialEq)]
struct DNSHeader {
    /// Packet Identifier (16 bits)
    id: u16,

    /// Query Response (1 bit)
    qr: DNSHeaderType,

    /// Operation Code (4 bits)
    opcode: u8,
    
    /// Authoritative answer (1 bit)
    aa: bool,
    
    /// Truncated Message (1 bit)
    tc: bool,
    
    /// Recursion desired (1 bit)
    rd: bool,

    /// Recursion available (1 bit)
    ra: bool,

    /// Reserved (3 bit)
    z: u8,

    /// Response Code (4 bit)
    rcode: ResultCode,

    /// Question Count (16 bit)
    qdcount: u16,

    /// Answer Count (16 bit)
    ancount: u16,

    /// Authority Count (16 bit)
    nscount: u16,

    /// Additional Count (16 bit)
    arcount: u16,
}

impl Parse for DNSHeader {
    fn parse(data: &[u8]) -> ParseResult<Self> {
        if data.len() < 12 {
            return Err(String::from(format!("DNSHeader parser: Expected data length to be at least {}", 12)));
        }

        // 2 bytes
        let id = u16::from_le_bytes([data[1], data[0]]);

        // 1 byte
            // 1 bit
        let qr     = (data[2] & 0b1000_0000) >> 7;
            // 4 bits
        let opcode = (data[2] & 0b0111_1000) >> 3;
            // 1 bit
        let aa     = (data[2] & 0b0000_0100) >> 2;
            // 1 bit
        let tc     = (data[2] & 0b0000_0010) >> 1;
            // 1 bit
        let rd     = (data[2] & 0b0000_0001) >> 0;
        
        // 1 byte
            // 1 bit
        let ra    = (data[3] & 0b1000_0000) >> 7;
            // 3 bits
        let z     = (data[3] & 0b0111_0000) >> 4;
            // 4 bits
        let rcode = (data[3] & 0b0000_1111) >> 0;

        // 2 bytes
        let qdcount = u16::from_le_bytes([data[5], data[4]]);

        // 2 bytes
        let ancount = u16::from_le_bytes([data[7], data[6]]);

        // 2 bytes
        let nscount = u16::from_le_bytes([data[9], data[8]]);

        // 2 bytes
        let arcount = u16::from_le_bytes([data[11], data[10]]);


        let header = DNSHeader {
            id,
            qr: if qr == 0 { DNSHeaderType::Query } else { DNSHeaderType::Response },
            opcode,
            aa: aa == 1,
            tc: tc == 1,
            rd: rd == 1,
            ra: ra == 1,
            z,
            rcode: (rcode as usize).into(),
            qdcount,
            ancount,
            nscount,
            arcount,
        };

        Ok((header, 12))
    }
}

#[derive(Debug, PartialEq)]
struct DNSQuestion {
    /// Domain name
    name: String,

    /// Record type (16 bit)
    rtype: u16,

    /// Class (16 bit)
    class: u16,
}

struct DNSQuestionsParser<'data> {
    packet: &'data [u8],
}

impl<'data> DNSQuestionsParser<'data> {
    pub fn new(packet: &'data [u8]) -> Self {
        Self { packet }
    }

    pub fn parse(&self, num_questions: usize, startptr: usize) -> ParseResult<Vec<DNSQuestion>> {
        let mut ptr = startptr;
        let mut result = vec![];
        
        for _ in 0..num_questions {
            let (question, len) = self.parse_question(ptr)?;

            result.push(question);

            ptr += len;
        }

        Ok((result, ptr - startptr))
    }

    fn parse_question(&self, ptr: usize) -> ParseResult<DNSQuestion> {
        let (name, consumed_len) = read_qname(self.packet, ptr)?;
        let end = ptr + consumed_len;

        Ok((
            DNSQuestion {
                name,
                rtype: u16::from_le_bytes([self.packet[end + 1], self.packet[end + 0]]),
                class: u16::from_le_bytes([self.packet[end + 3], self.packet[end + 2]]),
            },
            consumed_len + 2 + 2,
        ))
    }
}

#[derive(Debug, PartialEq)]
struct DNSRecord {
    /// Domain name
    name: String,

    /// Record type (16 bit)
    rtype: u16,

    /// Class (16 bit)
    class: u16,

    /// TTL (32 bit)
    ttl: u32,

    /// Length of the data (16 bit)
    len: u16,

    /// Record data (variable)
    record: DNSRecordData,
}

struct DNSRecordsParser<'data> {
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
            let (answer, len) = self.parse_answers(ptr)?;

            result.push(answer);

            ptr += len;
        }

        Ok((result, ptr - startptr))
    }

    fn parse_answers(&self, ptr: usize) -> ParseResult<DNSRecord> {
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

        let (record, record_len) = self.parse_record(
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

    fn parse_record(
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
enum DNSRecordData {
    A {
        ip: [u8; 4],
    },
    Unknown {
        data: Vec<u8>,
    },
}

#[derive(Debug)]
struct JumpInstructionMeta {
    source: usize,
}

#[derive(Debug)]
enum JumpInstruction {
    Label(JumpInstructionMeta)
}

#[derive(Debug)]
pub struct DNSPacket {
    header: DNSHeader,
    questions: Vec<DNSQuestion>,
    answers: Vec<DNSRecord>,
    authority: Vec<DNSRecord>,
    additional: Vec<DNSRecord>,
}

pub struct DNSPacketParser<'data> {
    packet: &'data [u8],
}

type DNSPacketParseError = String;

impl<'data> DNSPacketParser<'data> {
    pub fn new(data: &'data[u8]) -> Self {
        Self { packet: data }
    }

    pub fn parse(&self) -> Result<DNSPacket, DNSPacketParseError> {
        let mut ptr: usize = 0;

        let (header, header_size) = DNSHeader::parse(&self.packet[0..12])?;
        ptr += header_size;

        let questions = {
            if header.qdcount > 0 {
               let (questions, questions_size) = DNSQuestionsParser::new(self.packet)
                   .parse(header.qdcount as usize, ptr)?;

                ptr += questions_size;

                questions
            } else {
                vec![]
            }
        };

        let answers = {
            if header.ancount > 0 {
                let (answers, answers_size) = DNSRecordsParser::new(self.packet)
                    .parse(header.ancount as usize, ptr)?;

                ptr += answers_size;

                answers
            } else {
                vec![]
            }
        };

        let authority = {
            if header.nscount > 0 {
                let (authority, authority_size) = DNSRecordsParser::new(self.packet)
                    .parse(header.nscount as usize, ptr)?;

                ptr += authority_size;

                authority
            } else {
                vec![]
            }
        };

        let additional = {
            if header.arcount > 0 {
                let (additional, additional_size) = DNSRecordsParser::new(self.packet)
                    .parse(header.arcount as usize, ptr)?;

                ptr += additional_size;

                additional
            } else {
                vec![]
            }
        };

        Ok(DNSPacket {
            header,
            questions,
            answers,
            authority,
            additional,
        })
    }
}

// TODO: Look into Punycode for parsing Unicode
fn read_qname(data: &[u8], pos: usize) -> ParseResult<String> {
    let mut name = String::new();

    type Ptr = usize;
    type Level = usize;

    let mut queue: VecDeque<(Ptr, Level)> = VecDeque::from(vec![(pos, 0)]);
    let mut consumed_len = 0;

    // Resolve names recursively by using a queue
    while let Some((ptr, level)) = queue.pop_front() {
        if data[ptr] == 0 { // null character
            if level == 0 {
                consumed_len += 1;
            }

            continue;
        }

        // Is a string segment
        if data[ptr] >> 6 == 0b00 {
            let len = (data[ptr] & 0b0011_1111) as usize; // Length
            let slice = &data[(ptr + 1)..];
            let str_segment = &slice[0..len];
            name.push_str(&String::from_utf8_lossy(str_segment));
            name.push('.');

            queue.push_back((1 + ptr + len, level));

            if level == 0 {
                consumed_len += 1 + len;
            }

            continue;
        }

        // Is a pointer
        if data[ptr] >> 6 == 0b11 {
            let jumpptr = data[ptr + 1];

            queue.push_back((jumpptr as usize, level + 1));

            if level == 0 {
                consumed_len += 2;
            }

            continue;
        }
        
        return Err(String::from("DNSPacketParser: Unhandled qname marker"))
    }

    Ok((name, consumed_len))
}

#[cfg(test)]
mod tests {
    use crate::parser::{DNSQuestion, DNSRecord, DNSRecordData};

    use super::{DNSHeader, DNSHeaderType, Parse, DNSQuestionsParser, DNSRecordsParser, DNSPacketParser};

    static QUERY_SAMPLE1: &'static [u8] = &[0x86, 0xe6, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01];
    static RESP_SAMPLE1: &'static [u8] = &[0x86, 0xe6, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0xac, 0xd9, 0x12, 0xee];

    #[test]
    fn parses_header1() {
        let (actual_header, bytes_consumed) = DNSHeader::parse(QUERY_SAMPLE1).unwrap();
        
        let expected_header = DNSHeader {
            id: 34534,
            qr: DNSHeaderType::Query,
            opcode: 0,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            z: 2,
            rcode: 0,
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        };

        assert_eq!(12, bytes_consumed);
        assert_eq!(expected_header, actual_header);
    }

    #[test]
    fn parses_header2() {
        let (actual_header, bytes_consumed) = DNSHeader::parse(RESP_SAMPLE1).unwrap();
        
        let expected_header = DNSHeader {
            id: 34534,
            qr: DNSHeaderType::Response,
            opcode: 0,
            aa: false,
            tc: false,
            rd: true,
            ra: true,
            z: 0,
            rcode: 0,
            qdcount: 1,
            ancount: 1,
            nscount: 0,
            arcount: 0,
        };

        assert_eq!(12, bytes_consumed);
        assert_eq!(expected_header, actual_header);
    }

    #[test]
    fn parses_questions1() {
        let (questions, _) = DNSQuestionsParser::new(QUERY_SAMPLE1)
            .parse(1, 12)
            .unwrap();

        assert_eq!(
            vec![DNSQuestion { name: "google.com.".to_owned(), rtype: 1, class: 1 }],
            questions,
        )
    }

    #[test]
    fn parses_questions2() {
        let (questions, _) = DNSQuestionsParser::new(RESP_SAMPLE1)
            .parse(1, 12)
            .unwrap();

        assert_eq!(
            vec![DNSQuestion { name: "google.com.".to_owned(), rtype: 1, class: 1 }],
            questions,
        )
    }

    #[test]
    fn parses_answers() {
        let (answers, _) = DNSRecordsParser::new(RESP_SAMPLE1)
            .parse(1, 0x1C)
            .unwrap();

        assert_eq!(
            vec![DNSRecord {
                name: "google.com.".to_owned(),
                rtype: 1,
                class: 1,
                ttl: 300,
                len: 4,
                record: DNSRecordData::A { ip: [172, 217, 18, 238] },
            }],
            answers,
        )
    }

    #[test]
    fn parses_query_packet1() {
        let packet = DNSPacketParser::new(RESP_SAMPLE1)
            .parse()
            .unwrap();

        println!("DNSPacket: {:?}", packet);
    }
}
