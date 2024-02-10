use std::collections::HashMap;

use super::{header::DNSHeader, question::{DNSQuestion, DNSQuestionParser, DNSQuestionSerializer}, record::{DNSRecord, DNSRecordsParser, DNSRecordSerializer}, common::Parse, LabelPtrMap};


#[derive(Debug, PartialEq, Eq)]
pub struct DNSPacket {
    pub header: DNSHeader,
    pub questions: Vec<DNSQuestion>,
    pub answers: Vec<DNSRecord>,
    pub authority: Vec<DNSRecord>,
    pub additional: Vec<DNSRecord>,
}

impl DNSPacket {
    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        let mut data = Vec::new();
        let mut ptr = 0;

        // Serialize Header
        let serialized_header = self.header.serialize();
        let mut label_ptr_map: LabelPtrMap = HashMap::new();

        data.extend_from_slice(&serialized_header);
        ptr += serialized_header.len();


        // Serialize Questions
        let questions_data = DNSQuestionSerializer::new(
            &self.questions,
            &mut label_ptr_map,
            ptr,
        ).serialize()?;

        data.extend_from_slice(&questions_data);
        ptr += questions_data.len();
        
        let answers_data = DNSRecordSerializer::new(
            &self.answers,
            &mut label_ptr_map,
            ptr,
        ).serialize()?;

        data.extend_from_slice(&answers_data);
        ptr += answers_data.len();

        let authority_data = DNSRecordSerializer::new(
            &self.authority,
            &mut label_ptr_map,
            ptr
        ).serialize()?;

        data.extend_from_slice(&authority_data);
        ptr += authority_data.len();

        let additional_data = DNSRecordSerializer::new(
            &self.additional,
            &mut label_ptr_map,
            ptr
        ).serialize()?;

        data.extend_from_slice(&additional_data);

        Ok(data)
    }
}

pub struct DNSPacketParser<'data> {
    packet: &'data [u8],
    ptr: usize,
}

type DNSPacketParseError = String;

impl<'data> DNSPacketParser<'data> {
    pub fn new(data: &'data[u8]) -> Self {
        Self { packet: data, ptr: 0 }
    }

    fn parse_records(&mut self, count: usize) -> Result<Vec<DNSRecord>, String> {
        if count == 0 {
            return Ok(Vec::new());
        }

        let (records, records_size) = DNSRecordsParser::new(self.packet)
            .parse(count, self.ptr)?;

        self.ptr += records_size;

        Ok(records)
    }

    fn parse_questions(&mut self, count: usize) -> Result<Vec<DNSQuestion>, String> {
        if count == 0 {
            return Ok(Vec::new());
        }

        let (questions, questions_size) = DNSQuestionParser::new(self.packet)
           .parse(count, self.ptr)?;

        self.ptr += questions_size;

        Ok(questions)
    }

    fn parse_header(&mut self) -> Result<DNSHeader, String> {
        let (header, header_size) = DNSHeader::parse(&self.packet[0..12])?;
        self.ptr += header_size;

        Ok(header)
    }

    pub fn parse(&mut self) -> Result<DNSPacket, DNSPacketParseError> {
        let header = self.parse_header()?;

        let questions = self.parse_questions(header.qdcount as usize)?;
        let answers = self.parse_records(header.ancount as usize)?;
        let authority = self.parse_records(header.nscount as usize)?;
        let additional = self.parse_records(header.arcount as usize)?;

        Ok(DNSPacket {
            header,
            questions,
            answers,
            authority,
            additional,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::parser::{packet::DNSPacket, header::{DNSHeader, DNSHeaderType, ResultCode}, question::DNSQuestion};

    use super::DNSPacketParser;

    #[test]
    fn parses_and_serializes_simple_query_packet() {
        let query_packet_raw = fs::read("./samples/query_packet.bin")
            .expect("Should read query_packet sample file");

        let parsed_packet = DNSPacketParser::new(&query_packet_raw)
            .parse();

        assert_eq!(
            Ok(DNSPacket {
                header: DNSHeader {
                    id: 34534,
                    qr: DNSHeaderType::Query,
                    opcode: 0,
                    aa: false,
                    tc: false,
                    rd: true,
                    ra: false,
                    z: 2,
                    rcode: ResultCode::NoError,
                    qdcount: 1,
                    ancount: 0,
                    nscount: 0,
                    arcount: 0,
                },
                questions: vec![
                    DNSQuestion {
                        name: "google.com.".to_owned(),
                        rtype: 1,
                        class: 1,
                    },
                ],
                answers: vec![],
                authority: vec![],
                additional: vec![],
            }),
            parsed_packet,
        );

        assert_eq!(
            Ok(query_packet_raw),
            parsed_packet.and_then(|p| p.serialize()),
        );
    }

    #[test]
    fn parses_and_serializes_complex_response_packet() {
        let response_packet_raw = fs::read("./samples/response_packet_huge.bin")
            .expect("Should read response_packet_big sample file");

        let parsed_packet = DNSPacketParser::new(&response_packet_raw)
            .parse();

        println!("Parsed: {:#?}", parsed_packet);
        /*
        assert_eq!(
            Ok(DNSPacket {
                header: DNSHeader {
                    id: 34534,
                    qr: DNSHeaderType::Query,
                    opcode: 0,
                    aa: false,
                    tc: false,
                    rd: true,
                    ra: false,
                    z: 2,
                    rcode: ResultCode::NoError,
                    qdcount: 1,
                    ancount: 0,
                    nscount: 0,
                    arcount: 0,
                },
                questions: vec![
                    DNSQuestion {
                        name: "google.com.".to_owned(),
                        rtype: 1,
                        class: 1,
                    },
                ],
                answers: vec![],
                authority: vec![],
                additional: vec![],
            }),
            parsed_packet,
        );
        */
    }
}
