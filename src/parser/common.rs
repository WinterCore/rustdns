use std::collections::VecDeque;


pub type ParseResult<T> = Result<(
    T,     // Parsed object
    usize, // Consumed length
), String>;

pub trait Parse: Sized {
    fn parse(data: &[u8]) -> ParseResult<Self>;
}

impl DomainNameLabel {
    // TODO: Look into Punycode for parsing Unicode
    pub fn parse(data: &[u8], pos: usize) -> ParseResult<String> {
        let mut name = String::new();

        type Ptr = usize;
        type Level = usize;

        let mut queue: VecDeque<(Ptr, Level)> = VecDeque::from(vec![(pos, 0)]);
        let mut consumed_len = 0;

        // Resolve names recursively by using a queue
        while let Some((ptr, level)) = queue.pop_front() {
            if data[ptr] == 0 { // null character
                if level == 0 {
                    consumed_len += 1;
                }

                continue;
            }

            // Is a string segment
            if data[ptr] >> 6 == 0b00 {
                let len = (data[ptr] & 0b0011_1111) as usize; // Length
                let slice = &data[(ptr + 1)..];
                let str_segment = &slice[0..len];
                name.push_str(&String::from_utf8_lossy(str_segment));
                name.push('.');

                queue.push_back((1 + ptr + len, level));

                if level == 0 {
                    consumed_len += 1 + len;
                }

                continue;
            }

            // Is a pointer
            if data[ptr] >> 6 == 0b11 {
                let jumpptr = data[ptr + 1];

                queue.push_back((jumpptr as usize, level + 1));

                if level == 0 {
                    consumed_len += 2;
                }

                continue;
            }
            
            return Err(String::from("DNSPacketParser: Unhandled qname marker"))
        }

        Ok((name, consumed_len))
    }

    pub fn serialize(name:  ) {
    }
}

