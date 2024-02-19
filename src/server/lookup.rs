use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::fs;

use crate::parser::{header::{DNSHeader, DNSHeaderType, ResultCode}, packet::{DNSPacket, DNSPacketParser}, question::DNSQuestion};
use crate::parser::record::{DNSARecord, DNSRecordData, DNSRecordPack};


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
    
    fs::write("./their_response", &res_buffer[0..bytes_received])
        .expect("Should write their response");

    // println!("Bytes received {:?}", bytes_received);
    let resp_packet = DNSPacketParser::new(&res_buffer[0..bytes_received]).parse()?;
    
    Ok(resp_packet)
}

pub fn lookup_recursively(qname: &str, qtype: u16) -> Result<DNSPacket, String> {
    let mut server = SocketAddr::V4(
        SocketAddrV4::new(Ipv4Addr::new(192, 203, 230, 10), 53),
    );

    loop {
        let resp = lookup(server, qname, qtype)?;
        
        // We got our answers, we're done
        if ! resp.answers.is_empty() {
            return Ok(resp);
        }

        let ns_option = resp.authority
            .iter()
            .filter_map(|x| {
                if ! qname.ends_with(&x.name) {
                    return None;
                }

                match x.record {
                    DNSRecordData::NS(ref ns) => Some(ns.nsdname.clone()),
                    _ => None,
                }
            })
            .nth(0);

        let ns_domain = match ns_option {
            None => return Ok(resp),
            Some(name) => name,
        };

        println!("SERVER: {:?}", ns_domain);

        // Try to find it's ip in additional
        let ip_option = resp.additional
            .iter()
            .filter_map(|x| {
                if x.name != ns_domain {
                    return None;
                }

                match x.record {
                    DNSRecordData::A(ref rec) => Some(rec.ip),
                    _ => None,
                }
            }).nth(0);

        let ip = match ip_option {
            Some(ip) => ip,
            None => {
                let resp = lookup_recursively(&ns_domain, DNSARecord::RTYPE)?;
                let ip_option = resp.answers
                    .iter()
                    .filter_map(|x| {
                        match x.record {
                            DNSRecordData::A(ref rec) => Some(rec.ip),
                            _ => None,
                        }
                    }).nth(0);

                match ip_option {
                    Some(ip) => ip,
                    None => return Ok(resp),
                }
            },
        };

        server = SocketAddr::V4(
            SocketAddrV4::new(
                Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]),
                53,
            ),
        );
    }
}
