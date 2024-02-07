use crate::parser::common::DomainNameLabel;


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

impl DNSSOARecord {
    pub fn parse(data: &[u8], startptr: usize) -> Result<Self, String> {
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

    pub fn serialize(&self) -> Vec<u8> {
        vec![]
    }
}
