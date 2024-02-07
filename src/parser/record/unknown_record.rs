#[derive(Debug, PartialEq, Eq)]
pub struct DNSUnknownRecord {
    data: Vec<u8>,
}

impl DNSUnknownRecord {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        return Ok(Self { data: data.to_vec() })
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.data.to_vec()
    }
}

