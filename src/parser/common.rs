use std::{collections::{VecDeque, HashMap}, str::pattern::Pattern};

pub type LabelPtrMap = HashMap<String, usize>;

pub type ParseResult<T> = Result<(
    T,     // Parsed object
    usize, // Consumed length
), String>;

pub trait Parse: Sized {
    fn parse(data: &[u8]) -> ParseResult<Self>;
}

pub struct DomainNameLabel {}

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
            if data[ptr + 0] >> 6 == 0b11 {
                let jumpptr = u16::from_be_bytes([data[ptr + 0], data[ptr + 1]]) & (! (0b11 << 14));

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

    pub fn serialize(
        name: &str,
        label_ptr_map: Option<LabelPtrMap>,
    ) -> Result<(Vec<u8>, LabelPtrMap), String>  {
        if let Some(ptr) = label_ptr_map.and_then(|map| map.get(name)) {
            // TODO: This is actually 2 bytes. refer to common.rs:56
            let jumpbyte = (0b11 << 6) & ((*ptr as u8) & 0b00111111);

            return ()
        }

        let mut rest = name;
        let mut data = Vec::new();
        let mut ptr_map = HashMap::new();
        let mut ptr = 0;
        
        while ! rest.is_empty() {
            ptr_map.insert(rest.to_owned(), ptr);

            match rest.split_once('.') {
                Some((part, remainder)) => {
                    rest = remainder;

                    if part.len() > 0b0011_1111 {
                        return Err(format!("Domain label part {} exceeds the maximum length allowed", part));
                    }

                    data.push(part.len() as u8); // Push the length
                    data.extend_from_slice(part.as_bytes());


                    ptr += part.len() + 1;
                },
                None => return Err(format!("Invalid domain label {}", name)),
            }
        }


        // Push null character
        data.push(0);

        Ok((data, ptr_map))
    }
}

