use std::net::UdpSocket;

use crate::{parser::{header::{DNSHeader, DNSHeaderType, ResultCode}, packet::{DNSPacket, DNSPacketParser}}, server::lookup::lookup_recursively};

pub fn handle_query(socket: &UdpSocket) -> Result<(), String> {
    let mut packet_buf = [0u8; 65_535];
    println!("READY TO RECEIVE");
    let (bytes_read, src) = match socket.recv_from(&mut packet_buf) {
        Ok(len) => len,
        Err(er) => return Err("Failed to receive data from socket".to_owned()),
    };
    println!("RECEIVED QUERY FROM {:?}", src);

    let mut req_packet = DNSPacketParser::new(&packet_buf[0..bytes_read]).parse()?;

    let mut resp_packet = DNSPacket {
        header: DNSHeader {
            id: req_packet.header.id,
            qr: DNSHeaderType::Response,
            rd: true,
            ra: true,
            aa: false,
            tc: false,
            z: 0,
            opcode: 0,
            rcode: ResultCode::NoError,
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        },
        questions: req_packet.questions.clone(),
        answers: vec![],
        authority: vec![],
        additional: vec![],
    };

    if let Some(question) = req_packet.questions.pop() {
        match lookup_recursively(&question.name, question.rtype) {
            Ok(DNSPacket { header, questions: _, answers, authority, additional }) => {
                resp_packet.header.tc = header.tc;
                resp_packet.header.ancount = header.ancount;
                resp_packet.header.nscount = header.nscount;
                resp_packet.header.arcount = header.arcount;
                resp_packet.answers = answers;
                resp_packet.authority = authority;
                resp_packet.additional = additional;
                println!("Debug {:?}", resp_packet);

                socket.send_to(&resp_packet.serialize()?, src)
                    .expect("Should send response");
            }, 
            Err(err) => {
                resp_packet.header.rcode = ResultCode::ServerFailure;
                socket.send_to(&resp_packet.serialize()?, src)
                    .expect("Should send response");
            },
        }
    } else {
        resp_packet.header.rcode = ResultCode::FormatError;
        socket.send_to(&resp_packet.serialize()?, src)
            .expect("Should send response");
    }

    Ok(())
}
