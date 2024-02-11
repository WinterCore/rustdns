mod parser;

use std::io::Read;
use std::{fs, io};
use std::net::UdpSocket;

use parser::header::{DNSHeader, DNSHeaderType, ResultCode};
use parser::packet::DNSPacket;
use parser::question::DNSQuestion;

use crate::parser::Parse;
use crate::parser::packet::DNSPacketParser;
use crate::parser::record::DNSTXTRecord;
use crate::parser::record::DNSRecordPack;
// use parser::{DNSPacketParser, DNSPacket, DNSHeader, ResultCode, DNSHeaderType};

// use parser::header::;

fn main() {
    let socket = UdpSocket::bind("0.0.0.0:34000")
        .expect("Should create socket");

    let query_packet = DNSPacket {
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
                name: "yahoo.com.".to_owned(),
                rtype: DNSTXTRecord::RTYPE,
                class: 1,
            },
        ],
        answers: vec![],
        authority: vec![],
        additional: vec![],
    };
    
    socket.connect("68.180.131.16:53").unwrap();
    println!("Connected");
    let result = socket.send(&query_packet.serialize().unwrap());
    println!("Result: {:?}", result);

    println!("{:?}", query_packet.serialize());
    let mut buf: Vec<u8> = vec![0; 65_535];
    let res_size = socket.recv(&mut buf)
        .expect("Should receive response");

    println!("Received {} bytes: {:?}", res_size, buf.iter().take(res_size).collect::<Vec<&u8>>());

    let response = DNSPacketParser::new(&buf).parse().unwrap();
    println!("Response {:#?}", response);
}
