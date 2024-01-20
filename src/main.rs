mod parser;

use std::fs;
use parser::DNSPacketParser;

fn main() {
    let resp_packet_raw = fs::read("./response_packet_big.txt")
        .expect("Should read file");

    let packet = DNSPacketParser::new(&resp_packet_raw)
        .parse()
        .expect("Should parse dns packet");
    

    println!("Resp: {:?}", packet);
}
