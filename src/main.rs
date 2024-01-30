mod parser;

use std::{fs, io};
use std::net::UdpSocket;

use parser::header::{DNSHeader, DNSHeaderType, ResultCode};
use parser::packet::DNSPacket;
use parser::question::DNSQuestion;

use crate::parser::Parse;
// use parser::{DNSPacketParser, DNSPacket, DNSHeader, ResultCode, DNSHeaderType};

// use parser::header::;

fn main() {
    /*
    let socket = UdpSocket::bind("127.0.0.1:8080")
        .expect("Should create socket");

    socket.connect("198.41.0.4:53").expect("Should connect");
    */

    let query_packet = DNSPacket {
        header: DNSHeader {
            id: 334,
            qr: DNSHeaderType::Query,
            opcode: 0,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            z: 0,
            rcode: ResultCode::NoError,
            qdcount: 15,
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

    println!("{:?}", query_packet.serialize().unwrap().iter().map(|x| format!("{:x}", x)).collect::<Vec<String>>());

    /*
    loop {
        let mut buf: Vec<u8> = vec![0; 65_535];
        let res_size = socket.recv(&mut buf)
            .expect("Should receive response");

        println!("Received {} bytes: {:?}", res_size, buf);
    }
    */
}
