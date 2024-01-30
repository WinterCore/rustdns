use super::{header::DNSHeader, question::{DNSQuestion, DNSQuestionParser, DNSQuestionSerializer}, record::{DNSRecord, DNSRecordsParser}, common::Parse};


#[derive(Debug)]
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
        data.extend_from_slice(&serialized_header);
        ptr += serialized_header.len();

        // Serialize Questions
        let (
            questions_data,
            mut questions_label_ptr_map,
        ) = DNSQuestionSerializer::new(&self.questions).serialize()?;

        questions_label_ptr_map.iter_mut().for_each(|(_, x)| *x += ptr);
        data.extend_from_slice(&questions_data);
        ptr += questions_data.len();

        // Serialize the rest
        println!("{:?}", questions_label_ptr_map);

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
