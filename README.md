# RustDNS

<h4 align="center">Recursive DNS resolver implemented in Rust</h4>

A from-scratch recursive DNS resolver built in Rust as a learning project to understand how DNS works at the wire level.

## What it does

RustDNS is a recursive DNS resolver that:

- Listens for incoming DNS queries over UDP on port `8000`
- Resolves queries **recursively** by starting at a root nameserver (`192.203.230.10`) and following NS referrals until an answer is found
- Serializes and sends back a well-formed DNS response to the client

You can point any DNS client (e.g. `dig`) at `127.0.0.1:8000` and it will resolve the query for you.

## How to run

1. Install [Rust](https://www.rust-lang.org/tools/install)
2. Clone the repo:
   ```sh
   git clone git@github.com:WinterCore/rustdns.git
   cd rustdns
   ```
3. Start the server:
   ```sh
   cargo run
   ```
   The server binds to `0.0.0.0:8000`.

4. Query it from another terminal:
   ```sh
   dig @127.0.0.1 -p 8000 google.com
   ```

To run the tests:
```sh
cargo test
```

## What's implemented

### DNS Packet parsing & serialization
- Full DNS packet structure: header, questions, answers, authority, and additional sections
- DNS message compression (pointer labels) — both parsing and serializing with a label pointer map to avoid redundant domain name bytes

### DNS Header fields
- QR, Opcode, AA, TC, RD, RA, Z, RCODE
- Result codes: `NoError`, `FormatError`, `ServerFailure`, `NameError`, `NotImplemented`, `Refused`

### Record types
| Type | Description |
|------|-------------|
| `A` | IPv4 address |
| `AAAA` | IPv6 address |
| `NS` | Nameserver |
| `CNAME` | Canonical name alias |
| `MX` | Mail exchange |
| `TXT` | Text record |
| `SOA` | Start of authority |
| `Unknown` | Fallback for unrecognized types |

### Recursive resolution
- Starts resolution from a root nameserver
- Follows NS referrals through the authority section
- Resolves glue records (NS IPs) from the additional section, or recursively looks them up if not present
- Returns `ServerFailure` to the client on resolution errors
