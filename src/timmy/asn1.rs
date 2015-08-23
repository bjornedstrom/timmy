//! Simple parsing of ASN.1 DER

use timmy::tup::*;

use num::bigint::{BigInt, Sign};

#[derive(Debug)]
pub enum ASN1Error {
    MissingData(String),
    DecodeError(String),
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

enum TypeId {
    Null = 5,
    Boolean = 1,
    Sequence = 16,
    Set = 17,
    Integer = 2,
    Object = 6,
    BitString = 3,
    OctetString = 4,
    PrintableString = 19,
    UTCTime = 23,
    UTF8String = 12,
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

    fn parse_utf8_type(&self, raw: Vec<u8>) -> ASN1Result<String> {
        if let Ok(string) = String::from_utf8(raw) {
            Ok(string)
        } else {
            Err(ASN1Error::DecodeError("utf8 decode error".to_string()))
        }
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

        match tag {
            tag if tag == TypeId::Null as u8 => Ok(ASN1Type::Null),
            tag if tag == TypeId::Boolean as u8 => {
                let buf: Vec<u8> = raw;
                Ok(ASN1Type::Boolean(buf[0] == 0xff))
            }
            tag if tag == TypeId::Sequence as u8 => {
                let mut sub_parser = DerParser::new(&raw);
                let mut sequence = Vec::<ASN1Type>::new();
                loop {
                    let sub_ent = sub_parser.parse_entry();
                    match sub_ent {
                        Err(ASN1Error::MissingData(_)) => { break },
                        Err(err) => { return Err(err) }
                        Ok(ent) => { sequence.push(ent) }
                    }
                }
                Ok(ASN1Type::Sequence(sequence))
            },
            tag if tag == TypeId::Set as u8 => {
                let mut sub_parser = DerParser::new(&raw);
                let mut sequence = Vec::<ASN1Type>::new();
                loop {
                    let sub_ent = sub_parser.parse_entry();
                    match sub_ent {
                        Err(ASN1Error::MissingData(_)) => { break },
                        Err(err) => { return Err(err) }
                        Ok(ent) => { sequence.push(ent) }
                    }
                }
                Ok(ASN1Type::Set(sequence))
            },
            tag if tag == TypeId::Integer as u8 => Ok(ASN1Type::Integer(BigInt::from_bytes_be(Sign::Plus, &raw))),
            tag if tag == TypeId::Object as u8 => {
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
                if let Some(tup) = vec_to_tup(&oi) {
                    Ok(ASN1Type::Object(tup))
                } else {
                    Err(ASN1Error::DecodeError("object decode error".to_string()))
                }
            },
            tag if tag == TypeId::BitString as u8 => Ok(ASN1Type::BitString(raw)),
            tag if tag == TypeId::OctetString as u8 => Ok(ASN1Type::OctetString(raw)),
            tag if tag == TypeId::PrintableString as u8 => {
                let string = try!(self.parse_utf8_type(raw));
                Ok(ASN1Type::PrintableString(string))
            },
            tag if tag == TypeId::UTCTime as u8 => {
                let string = try!(self.parse_utf8_type(raw));
                Ok(ASN1Type::UTCTime(string))
            },
            tag if tag == TypeId::UTF8String as u8 => {
                let string = try!(self.parse_utf8_type(raw));
                Ok(ASN1Type::UTF8String(string))
            },
            _ => {
                println!("Got Unknown ASN1 Type {} {} {} {}", class_bits, constructed, tag, length);
                Ok(ASN1Type::Unknown)
            }
        }
    }
}
