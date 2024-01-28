use std::{collections::HashMap};

use super::common::{ParseResult, DomainNameLabel};


#[derive(Debug, PartialEq)]
pub struct DNSQuestion {
    /// Domain name
    pub name: String,

    /// Record type (16 bit)
    pub rtype: u16,

    /// Class (16 bit)
    pub class: u16,
}

pub struct DNSQuestionsParser<'data> {
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
        let (name, consumed_len) = DomainNameLabel::parse(self.packet, ptr)?;
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

pub struct DNSQuestionsSerializer<'data> {
    dns_questions: &'data [DNSQuestion],
}

impl<'data> DNSQuestionsSerializer<'data> {
    pub fn new(dns_questions: &'data [DNSQuestion]) -> Self {
        Self { dns_questions }
    }

    pub fn serialize(&self) -> Result<(Vec<u8>, HashMap<String, usize>), String> {
        let mut ptr = 0;
        let mut ptr_map = HashMap::new();
        let mut data = Vec::new();

        for question in self.dns_questions {
            let (serialized_name, mut name_ptr_map) = DomainNameLabel::serialize(&question.name)?;
            name_ptr_map.iter_mut().for_each(|(_, x)| *x += ptr);
            ptr_map.extend(name_ptr_map);

            data.extend_from_slice(&serialized_name);
            ptr += serialized_name.len();
        }

        Ok((data, ptr_map))
    }
}
