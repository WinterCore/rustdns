
use crate::parser::common::{Parse, ParseResult};

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum DNSHeaderType {
    Query = 0,
    Response = 1,
}

impl Into<usize> for DNSHeaderType {
    fn into(self) -> usize {
        match self {
            Self::Query => 0,
            Self::Response => 1,
        }
    }
}

impl From<usize> for DNSHeaderType {
    fn from(value: usize) -> Self {
        match value {
            0 => Self::Query,
            1 => Self::Response,
            _ => panic!("DNSHeaderType: Unknown type"),
        }
    }
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
pub struct DNSHeader {
    /// Packet Identifier (16 bits)
    pub id: u16,

    /// Query Response (1 bit)
    pub qr: DNSHeaderType,

    /// Operation Code (4 bits)
    pub opcode: u8,
    
    /// Authoritative answer (1 bit)
    pub aa: bool,
    
    /// Truncated Message (1 bit)
    pub tc: bool,
    
    /// Recursion desired (1 bit)
    pub rd: bool,

    /// Recursion available (1 bit)
    pub ra: bool,

    /// Reserved (3 bit)
    pub z: u8,

    /// Response Code (4 bit)
    pub rcode: ResultCode,

    /// Question Count (16 bit)
    pub qdcount: u16,

    /// Answer Count (16 bit)
    pub ancount: u16,

    /// Authority Count (16 bit)
    pub nscount: u16,

    /// Additional Count (16 bit)
    pub arcount: u16,
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

impl DNSHeader {
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = vec![0u8; 12];

        data.extend_from_slice(&self.id.to_le_bytes());

        data.push(
            ((Into::<usize>::into(self.qr) as u8) << 7) |
            (self.opcode                          << 3) |
            (Into::<u8>::into(self.aa)            << 2) |
            (Into::<u8>::into(self.tc)            << 1) |
            (Into::<u8>::into(self.rd)            << 0)
        );

        data.push(
            Into::<u8>::into(self.ra)                << 7 |
            (self.z                                  << 4) |
            ((Into::<usize>::into(self.rcode) as u8) << 0)
        );

        data.extend_from_slice(&self.qdcount.to_le_bytes());
        data.extend_from_slice(&self.ancount.to_le_bytes());
        data.extend_from_slice(&self.nscount.to_le_bytes());
        data.extend_from_slice(&self.arcount.to_le_bytes());

        data
    }
}
