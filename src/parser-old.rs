use std::{collections::VecDeque, iter::Map};


#[cfg(test)]
mod tests {
    use crate::parser::{DNSQuestion, DNSRecord, DNSRecordData, ResultCode};

    use super::{DNSHeader, DNSHeaderType, Parse, DNSQuestionsParser, DNSRecordsParser, DNSPacketParser};

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
            rcode: ResultCode::NoError,
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
            rcode: ResultCode::NoError,
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
        let (questions, _) = DNSQuestionsParser::new(QUERY_SAMPLE1)
            .parse(1, 12)
            .unwrap();

        assert_eq!(
            vec![DNSQuestion { name: "google.com.".to_owned(), rtype: 1, class: 1 }],
            questions,
        )
    }

    #[test]
    fn parses_questions2() {
        let (questions, _) = DNSQuestionsParser::new(RESP_SAMPLE1)
            .parse(1, 12)
            .unwrap();

        assert_eq!(
            vec![DNSQuestion { name: "google.com.".to_owned(), rtype: 1, class: 1 }],
            questions,
        )
    }

    #[test]
    fn parses_answers() {
        let (answers, _) = DNSRecordsParser::new(RESP_SAMPLE1)
            .parse(1, 0x1C)
            .unwrap();

        assert_eq!(
            vec![DNSRecord {
                name: "google.com.".to_owned(),
                rtype: 1,
                class: 1,
                ttl: 300,
                len: 4,
                record: DNSRecordData::A { ip: [172, 217, 18, 238] },
            }],
            answers,
        )
    }

    #[test]
    fn parses_query_packet1() {
        let packet = DNSPacketParser::new(RESP_SAMPLE1)
            .parse()
            .unwrap();

        println!("DNSPacket: {:?}", packet);
    }
}
