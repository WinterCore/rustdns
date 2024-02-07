mod parser;

use std::io::Read;
use std::{fs, io};
use std::net::UdpSocket;

use parser::header::{DNSHeader, DNSHeaderType, ResultCode};
use parser::packet::DNSPacket;
use parser::question::DNSQuestion;

use crate::parser::Parse;
use crate::parser::packet::DNSPacketParser;
// use parser::{DNSPacketParser, DNSPacket, DNSHeader, ResultCode, DNSHeaderType};

// use parser::header::;

fn main() {
    let socket = UdpSocket::bind("0.0.0.0:34000")
        .expect("Should create socket");

    // socket.connect("8.8.8.8:53").expect("Should connect");

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
                name: "google.com.".to_owned(),
                rtype: 1,
                class: 1,
            },
        ],
        answers: vec![],
        authority: vec![],
        additional: vec![],
    };
    
    socket.connect("8.8.8.8:53").unwrap();
    println!("Connected");
    let result = socket.send(&query_packet.serialize().unwrap());
    println!("Result: {:?}", result);

    let mut buf: Vec<u8> = vec![0; 65_535];
    let res_size = socket.recv(&mut buf)
        .expect("Should receive response");

    println!("Received {} bytes: {:?}", res_size, buf.iter().take(res_size).collect::<Vec<&u8>>());

    let response = DNSPacketParser::new(&buf).parse().unwrap();
    println!("Response {:?}", response);
}
