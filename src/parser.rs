#[derive(Debug)]
enum DNSHeaderType {
    Query,
    Response,
}

#[derive(Debug)]
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


struct DNSPacketParser<'data> {
    pos: usize,
    data: &'data [u8],
}

impl<'data> DNSPacketParser<'data> {
    fn new(data: &'data[u8]) -> Self {
        Self { pos: 0, data }
    }
}
