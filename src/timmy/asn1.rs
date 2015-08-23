//! Simple parsing of ASN.1 DER

use timmy::tup::*;

use num::bigint::{BigInt, Sign};

#[derive(Debug)]
pub enum ASN1Error {
    MissingData(String),
}

pub type ASN1Result<T> = Result<T, ASN1Error>;

#[derive(Debug)]
pub enum ASN1Type {
    Unknown,
    Cont(u8, Box<ASN1Type>),
    Null,
    Boolean(bool),
    Sequence(Vec<ASN1Type>),
    Set(Vec<ASN1Type>),
    Object(TupT<u32>),
    Integer(BigInt),
    BitString(Vec<u8>),
    OctetString(Vec<u8>),
    PrintableString(String),
    UTF8String(String),
    UTCTime(String),
}

pub fn asn1_to_raw_string(obj: &ASN1Type) -> Option<String> {
    match obj {
        &ASN1Type::PrintableString(ref string) => Some(string.clone()),
        &ASN1Type::UTF8String(ref string) => Some(string.clone()),
        _ => None,
    }
}

pub fn asn1_to_raw_integer(obj: &ASN1Type) -> Option<BigInt> {
    match obj {
        &ASN1Type::Integer(ref bigint) => Some(bigint.clone()),
        _ => None,
    }
}

pub struct DerParser {
    buf: Vec<u8>,
    idx: usize,
}

impl DerParser {
    pub fn new(der: &Vec<u8>) -> DerParser {
        DerParser {
            buf: der.clone(),
            idx: 0,
        }
    }

    fn check_buffer(&mut self) -> ASN1Result<()> {
        if self.idx >= self.buf.len() {
            return Err(ASN1Error::MissingData("length".to_string()));
        }
        Ok(())
    }

    fn get_length(&mut self) -> ASN1Result<usize> {
        try!(self.check_buffer());

        let len_tmp = self.buf[self.idx];
        if len_tmp <= 127 {
            self.idx += 1;
            return Ok(len_tmp as usize);
        }

        let len_octets = len_tmp & 127;
        assert!(len_octets <= 3);
        let mut length = 0 as usize;
        self.idx += 1;
        for _ in 0..len_octets {
            length <<= 8;
            try!(self.check_buffer());
            length |= self.buf[self.idx] as usize;
            self.idx += 1;
        }
        Ok(length)
    }

    fn parse_header(&mut self) -> ASN1Result<(u8, bool, u8, usize)> {
        try!(self.check_buffer());

        let c = self.buf[self.idx];
        let tag = c & 31;
        let p_c = (c >> 5) & 1;
        let class_ = (c >> 6) & 3;
        assert!(tag != 31);
        self.idx += 1;
        let length = try!(self.get_length());

        Ok((class_ as u8, p_c == 1, tag as u8, length as usize))
    }

    pub fn parse_entry(&mut self) -> ASN1Result<ASN1Type> {
        try!(self.check_buffer());

        let (class_bits, constructed, tag, length) = try!(self.parse_header());

        assert!(class_bits == 0 || class_bits == 2);

        match class_bits {
            0 => {
            }
            2 => {
                let pos = self.idx;
                self.idx += length;

                assert!(pos + length <= self.buf.len());

                let sub_buf = self.buf[pos..pos+length].iter().cloned().collect();
                let mut sub_parser = DerParser::new(&sub_buf);
                let sub_entry = try!(sub_parser.parse_entry());
                return Ok(ASN1Type::Cont(tag, Box::new(sub_entry)));
            }
            _ => {
                panic!("Parsing this not implemented.");
            }
        }

        let pos = self.idx;
        self.idx += length;

        assert!(pos + length <= self.buf.len());

        let raw = self.buf[pos..pos+length].iter().cloned().collect();

        let entry = match tag {
            5 => ASN1Type::Null,
            1 => {
                let buf: Vec<u8> = raw;
                ASN1Type::Boolean(buf[0] == 0xff)
            }
            16 => {
                let mut sub_parser = DerParser::new(&raw);
                let mut sequence = Vec::<ASN1Type>::new();
                loop {
                    let sub_ent = sub_parser.parse_entry();
                    match sub_ent {
                        Err(ASN1Error::MissingData(_)) => { break },
                        Ok(ent) => { sequence.push(ent) }
                    }
                }
                ASN1Type::Sequence(sequence)
            },
            17 => {
                let mut sub_parser = DerParser::new(&raw);
                let mut sequence = Vec::<ASN1Type>::new();
                loop {
                    let sub_ent = sub_parser.parse_entry();
                    match sub_ent {
                        Err(ASN1Error::MissingData(_)) => { break },
                        Ok(ent) => { sequence.push(ent) }
                    }
                }
                ASN1Type::Set(sequence)
            },
            2 => ASN1Type::Integer(BigInt::from_bytes_be(Sign::Plus, &raw)),
            6 => {
                let mut oi = Vec::<u32>::new();
                let obj_bytes = raw;
                oi.push((obj_bytes[0] / 40) as u32);
                oi.push((obj_bytes[0] % 40) as u32);
                let mut i = 1;
                while i < obj_bytes.len() {
                    if obj_bytes[i] <= 127 {
                        oi.push(obj_bytes[i] as u32);
                        i += 1;
                    } else {
                        let mut next_sub_id: u32 = obj_bytes[i] as u32;
                        let mut sub_id: u32 = 0;
                        i += 1;
                        while next_sub_id > 127 {
                            sub_id <<= 7;
                            sub_id |= next_sub_id & 127;
                            next_sub_id = obj_bytes[i] as u32;
                            i += 1;
                        }
                        oi.push((sub_id << 7) | next_sub_id);
                    }
                }
                ASN1Type::Object(vec_to_tup(&oi).expect("..."))
            },
            3 => ASN1Type::BitString(raw),
            4 => ASN1Type::OctetString(raw),
            19 => ASN1Type::PrintableString(String::from_utf8(raw).unwrap()),
            23 => ASN1Type::UTCTime(String::from_utf8(raw).unwrap()),
            12 => ASN1Type::UTF8String(String::from_utf8(raw).unwrap()),
            _ => {
                println!("Got Unknown ASN1 Type {} {} {} {}", class_bits, constructed, tag, length);
                ASN1Type::Unknown
            }
        };

        Ok(entry)
    }
}
