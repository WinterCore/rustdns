use std::net::{SocketAddr, UdpSocket};

use crate::parser::{header::{DNSHeader, DNSHeaderType, ResultCode}, packet::{DNSPacket, DNSPacketParser}, question::DNSQuestion};


pub fn lookup(server: SocketAddr, qname: &str, qtype: u16) -> Result<DNSPacket, String> {
    let socket = UdpSocket::bind("0.0.0.0:50000").expect("Should bind socket");

    let header = DNSHeader {
        id: 6666,
        qr: DNSHeaderType::Query,
        opcode: 0,
        aa: false,
        tc: false,
        rd: true,
        ra: false,
        z: 0,
        rcode: ResultCode::NoError,
        qdcount: 1,
        ancount: 0,
        nscount: 0,
        arcount: 0,
    };

    let questions: Vec<DNSQuestion> = vec![
        DNSQuestion {
            name: qname.to_string(),
            class: 1,
            rtype: qtype,
        },
    ];

    let query_packet = DNSPacket {
        header,
        questions,
        answers: vec![],
        authority: vec![],
        additional: vec![],
    };
    // println!("QUERY PACKET BIN: {:02x?}", query_packet.serialize().unwrap());
    
    socket.connect(server).map_err(|e| format!("Socket failed to connect to {}, {}", server, e))?;
    socket.send(&query_packet.serialize()?)
        .map_err(|e| format!("Failed to send packet to {}, {}", server, e))?;
    // println!("Query was sent");

    let mut res_buffer = [0u8; 66_000];
    let bytes_received = socket.recv(&mut res_buffer)
        .map_err(|e| format!("Failed to receive response from {}, {}", server, e))?;
    

    // println!("Bytes received {:?}", bytes_received);
    let resp_packet = DNSPacketParser::new(&res_buffer[0..bytes_received]).parse()?;
    
    Ok(resp_packet)
}
