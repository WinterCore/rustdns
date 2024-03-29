use super::DNSRecordPack;


#[derive(Debug, PartialEq, Eq)]
pub struct DNSTXTRecord {
    text: String,
}

impl DNSRecordPack for DNSTXTRecord {
    const RTYPE: u16 = 16;

    fn parse(
        data: &[u8],
        startptr: usize,
        len: usize,
    ) -> Result<Self, String> where Self: Sized {
        let mut text = String::new();
        let mut ptr: usize = 0;

        while ptr < len {
            let seg_len = data[startptr + ptr] as usize;
            let segment = String::from_utf8_lossy(
                &data[(startptr + ptr + 1)..(startptr + ptr + 1 + seg_len)]
            ).to_string();
            text.push_str(&segment);

            ptr += seg_len + 1;
        }

        Ok(Self { text })
    }

    fn serialize(
        &self,
        _label_ptr_map: &mut crate::parser::LabelPtrMap,
        _ptr: usize,
    ) -> Result<Vec<u8>, String> {
        let mut data: Vec<u8> = vec![];
        let mut str_ptr: usize = 0;

        let str_bytes = self.text.as_bytes();
        let total_len = self.text.len();

        while str_ptr < total_len {
            let seg_len = total_len.min(255);

            data.push(seg_len as u8);
            data.extend_from_slice(&str_bytes[str_ptr..(str_ptr + seg_len)]);

            str_ptr += seg_len;
        }

        Ok(data)
    }
}
