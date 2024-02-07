#[derive(Debug, PartialEq, Eq)]
pub struct DNSARecord { ip: [u8; 4] }

impl DNSARecord {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        let ip = [data[0], data[1], data[2], data[3]];

        return Ok(Self { ip })
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.ip.to_vec()
    }
}
