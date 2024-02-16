mod parser;
mod server;

use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};


use crate::server::server::handle_query;

fn main() {
    let socket = UdpSocket::bind(("0.0.0.0", 8000))
        .expect("Should bind server");

    loop {
        handle_query(&socket).unwrap();
    }
}
