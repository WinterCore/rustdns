use std::collections::VecDeque;


type ParseResult<T> = (
    T,     // Parsed object
    usize, // Consumed length
);

pub trait Parse: Sized {
    // -> (Self, Bytes consumed)
    fn parse(data: &[u8]) -> Result<ParseResult<Self>, String>;
}

#[derive(Debug, PartialEq)]
enum DNSHeaderType {
    Query,
    Response,
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
    rcode: u8,

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
    fn parse(data: &[u8]) -> Result<ParseResult<Self>, String> {
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
            rcode,
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

    pub fn parse(&self, num_questions: usize, startptr: usize) -> Result<Vec<DNSQuestion>, String> {
        let mut ptr = startptr;
        let mut result = vec![];
        
        for _ in 0..num_questions {
            let (question, len) = self.parse_question(ptr)?;

            result.push(question);

            ptr += len;
        }

        Ok(result)
    }

    fn parse_question(&self, ptr: usize) -> Result<ParseResult<DNSQuestion>, String> {
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

#[derive(Debug)]
struct DNSAnswer {
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
    record: DNSRecord,
}

struct DNSAnswersParser<'data> {
    packet: &'data [u8],
}

impl<'data> DNSAnswersParser<'data> {
    pub fn new(packet: &'data [u8]) -> Self {
        Self { packet }
    }

    pub fn parse(&self, num_answers: usize, startptr: usize) -> Result<Vec<DNSAnswer>, String> {
        let mut ptr = startptr;
        let mut result = vec![];
        
        for _ in 0..num_answers {
            let (answer, len) = self.parse_answers(ptr)?;

            result.push(answer);

            ptr += len;
        }

        Ok(result)
    }

    fn parse_answers(&self, ptr: usize) -> Result<ParseResult<DNSAnswer>, String> {
        let (name, consumed_len) = read_qname(self.packet, ptr)?;
        println!("Debug: {:?}, {:?}", name, consumed_len);
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

        let (record, record_len) = self.parse_record(len as usize, end + 10)?;

        Ok((
            DNSAnswer {
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

    fn parse_record(&self, len: usize, ptr: usize) -> Result<ParseResult<DNSRecord>, String> {
        if len == 4 {
            let ip = [
                self.packet[ptr + 0],
                self.packet[ptr + 1],
                self.packet[ptr + 2],
                self.packet[ptr + 3],
            ];

            return Ok((DNSRecord::IP(DNSIPRecord { ip }), 4))
        }

        Err(format!("DNSAnswersParser unhandled record length {}", len))
    }
}

#[derive(Debug)]
struct DNSIPRecord {
    ip: [u8; 4],
}

#[derive(Debug)]
enum DNSRecord {
    IP(DNSIPRecord),
}

#[derive(Debug)]
struct JumpInstructionMeta {
    source: usize,
}

#[derive(Debug)]
enum JumpInstruction {
    Label(JumpInstructionMeta)
}

struct DNSPacketData {
    header: DNSHeader,
    questions: Vec<DNSQuestion>,
    answers: Vec<DNSAnswer>,
}

enum DNSPacket {
    Question(DNSPacketData)
}

struct DNSPacketParser<'data> {
    packet: &'data [u8],
}

type DNSPacketParseError = String;

impl<'data> DNSPacketParser<'data> {
    pub fn new(data: &'data[u8]) -> Self {
        Self { packet: data }
    }

    pub fn parse(&self) -> Result<(), DNSPacketParseError> {
        let mut ptr: usize = 0;

        let (header, header_size) = DNSHeader::parse(&self.packet[0..12])?;
        ptr += header_size;

        let questions = DNSQuestionsParser::new(self.packet)
            .parse(
                header.qdcount as usize,
                ptr,
            )?;

        Ok(())
    }
}

// TODO: Look into Punycode for parsing Unicode
fn read_qname(data: &[u8], pos: usize) -> Result<ParseResult<String>, String> {
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
    use crate::parser::DNSQuestion;

    use super::{DNSHeader, DNSHeaderType, Parse, DNSQuestionsParser, DNSAnswersParser};

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
        let questions = DNSQuestionsParser::new(QUERY_SAMPLE1)
            .parse(1, 12)
            .unwrap();

        assert_eq!(
            vec![DNSQuestion { name: "google.com.".to_owned(), rtype: 1, class: 1 }],
            questions,
        )
    }

    #[test]
    fn parses_questions2() {
        let questions = DNSQuestionsParser::new(RESP_SAMPLE1)
            .parse(1, 12)
            .unwrap();

        assert_eq!(
            vec![DNSQuestion { name: "google.com.".to_owned(), rtype: 1, class: 1 }],
            questions,
        )
    }

    #[test]
    fn parses_answers() {
        let answers = DNSAnswersParser::new(RESP_SAMPLE1)
            .parse(1, 0x1C)
            .unwrap();

        println!("Answers: {:?}", answers);
    }
}
