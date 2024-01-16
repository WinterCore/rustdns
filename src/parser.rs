
pub trait Parser {
    // -> (Bytes consumed, Self)
    fn parse(data: &[u8]) -> (usize, Self);
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

impl Parser for DNSHeader {
    fn parse(data: &[u8]) -> (usize, Self) {
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

        (12, header)
    }
}

#[derive(Debug)]
struct DNSQuestion {
    /// Domain name
    name: String,

    /// Record type (16 bit)
    rtype: u16,

    /// Class (16 bit)
    class: u16,
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
    pos: usize, // Might not be needed
    data: &'data [u8],
}

impl<'data> DNSPacketParser<'data> {
    pub fn new(data: &'data[u8]) -> Self {
        Self { pos: 0, data }
    }

    pub fn parse(&mut self) {
        let header = DNSHeader::parse(&self.data[0..12]);
    }
}

#[cfg(test)]
mod tests {
    use super::{DNSHeader, DNSHeaderType, Parser};

    static QUERY_SAMPLE1: &'static [u8] = &[0x86, 0xe6, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01];
    static RESP_SAMPLE1: &'static [u8] = &[0x86, 0xe6, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0xac, 0xd9, 0x12, 0xee];

    #[test]
    fn parses_query_header1() {
        let (bytes_consumed, actual_header) = DNSHeader::parse(QUERY_SAMPLE1);
        
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
    fn parses_response_header1() {
        let (bytes_consumed, actual_header) = DNSHeader::parse(RESP_SAMPLE1);
        
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
}
