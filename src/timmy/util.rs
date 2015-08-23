//! Some utility stuff.

use chrono::datetime::DateTime;
use chrono::naive::datetime::NaiveDateTime;
use chrono::offset::utc::UTC;
use crypto::digest::Digest;
use std::io::Read;

pub struct SimpleBinaryWriter {
    pub buf: Vec<u8>,
}

impl SimpleBinaryWriter {
    pub fn new() -> SimpleBinaryWriter {
        SimpleBinaryWriter {
            buf: Vec::new(),
        }
    }

    pub fn put_u8(&mut self, a: u8) {
        self.buf.push(a);
    }

    pub fn put_u16(&mut self, a: u16) {
        self.put_u8((a >> 8) as u8);
        self.put_u8((a & 0xff) as u8);
    }

    pub fn put_u24(&mut self, a: u32) {
        self.put_u8(((a >> 16) & 0xff) as u8);
        self.put_u8(((a >> 8) & 0xff) as u8);
        self.put_u8((a & 0xff) as u8);
    }
}

pub struct BinaryParser<'a> {
    //buf: &'a [u8],
    buf: Vec<u8>,
    idx: usize,
    reader: &'a mut Read,
}

impl<'a> BinaryParser<'a> {
    pub fn new(reader: &'a mut Read) -> BinaryParser {
        BinaryParser {
            buf: Vec::new(),
            idx: 0,
            reader: reader,
        }
    }

    pub fn tell(&mut self) -> usize {
        self.idx
    }

    pub fn seek(&mut self, pos: usize) {
        self.idx = pos
    }

    fn buffer_up(&mut self) {
        let mut arr: [u8; 4096] = [0; 4096];

        match self.reader.read(&mut arr) {
            Ok(size) => {
                //println!("read {} bytes", size);

                self.buf.extend(arr[0..size].iter().cloned());
            }
            // Makes sense?
            Err(_) => { panic!("read failure!!!"); }
        };
    }

    // TODO: This will grow forever: we should purge bytes already
    // read after a while.
    pub fn take(&mut self, num: usize) -> &[u8] {
        let cur = self.idx;
        self.idx = self.idx + num;

        while self.buf.len() < self.idx {
            self.buffer_up();
        }

        &self.buf[cur .. self.idx]
    }

    /*
    fn read_u32(&mut self) -> u32 {
        let raw: &[u8] = self.take(4);

        ((raw[0] as u32) << 24) |
        ((raw[1] as u32) << 16) |
        ((raw[2] as u32) << 8) |
        (raw[3] as u32)
    }
    */

    pub fn read_u24(&mut self) -> u32 {
        let raw: &[u8] = self.take(3);

        ((raw[0] as u32) << 16) |
        ((raw[1] as u32) << 8) |
        (raw[2] as u32)
    }

    pub fn read_u16(&mut self) -> u16 {
        let raw: &[u8] = self.take(2);

        ((raw[0] as u16) << 8) |
        (raw[1] as u16)
    }

    pub fn read_u8(&mut self) -> u8 {
        let raw: &[u8] = self.take(1);

        raw[0]
    }
}

pub fn timestamp_to_datetime(unix_timestamp: u32) -> DateTime<UTC> {
    let naive_ts = NaiveDateTime::from_timestamp(unix_timestamp as i64, 0);
    let ts = DateTime::<UTC>::from_utc(naive_ts, UTC);
    ts
}

pub fn to_hex_string(bytes: &Vec<u8>) -> String {
    let strs: Vec<String> = bytes.iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    strs.connect("")
}

pub fn hash_content<R: Read, D: Digest>(file_handle: &mut R, hasher: &mut D) {
    let mut buf: [u8; 4096] = [0; 4096];

    loop {
        match file_handle.read(&mut buf) {
            Ok(0) => { break }
            Ok(size) => {
                hasher.input(&mut buf[0..size]);
            }
            // Makes sense?
            Err(_) => { break }
        };
    }
}
