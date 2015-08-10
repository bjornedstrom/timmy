extern crate crypto;
extern crate getopts;
extern crate chrono;
extern crate rustc_serialize;

use self::crypto::digest::Digest;
use self::crypto::sha2::Sha256;
use getopts::Options;
use std::env;
use std::io;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::net::TcpStream;
use chrono::naive::datetime::NaiveDateTime;
use chrono::offset::utc::UTC;
use chrono::datetime::DateTime;
use std::path::Path;
use rustc_serialize::base64::{STANDARD, ToBase64};
use rustc_serialize::json::{self, Json, ToJson};
use std::collections::HashMap;
use std::collections::BTreeMap;

enum TLSMessageType {
    Handshake = 22,
}

enum TLSHandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    Certificate = 11,
    ServerKeyExchange = 12,
}


/*
pub struct ClientHello {
    header: u32,
    client_random: &[u8; 32],
    cipher_suits: Vec<u16>,
    compression: Vec<u8>,
    //extensions:
}

impl ClientHello {
    pub fn size(&self) -> uint {
        return 32 + 
    }
}
*/

fn timestamp_to_datetime(unix_timestamp: u32) -> DateTime<UTC> {
    let naive_ts = NaiveDateTime::from_timestamp(unix_timestamp as i64, 0);
    let ts = DateTime::<UTC>::from_utc(naive_ts, UTC);
    ts
}

pub fn to_hex_string(bytes: Vec<u8>) -> String {
    let strs: Vec<String> = bytes.iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    strs.connect("")
}

struct X509Certificate {
    buf: Vec<u8>,
}

impl X509Certificate {
    fn new(der: Vec<u8>) -> X509Certificate {
        X509Certificate {
            buf: der,
        }
    }
}

struct TLSHandshake {
    client_random: Vec<u8>,
    server_random: Vec<u8>,
    certs: Vec<X509Certificate>,
    cipher: u16,
    signed_blob: Vec<u8>,
    signature: Vec<u8>,
}

impl TLSHandshake {
    fn new() -> TLSHandshake {
        TLSHandshake {
            client_random: Vec::new(),
            server_random: Vec::new(),
            certs: Vec::new(),
            cipher: 0,
            signed_blob: Vec::new(),
            signature: Vec::new(),
        }
    }

    fn get_signature(&self) -> &Vec<u8> {
        &self.signature
    }

    fn get_unix_timestamp(&self) -> u32 {
        let raw = &self.server_random;

        ((raw[0] as u32) << 24) |
        ((raw[1] as u32) << 16) |
        ((raw[2] as u32) << 8) |
        (raw[3] as u32)
    }

    fn parse_header(&mut self, parser: &mut BinaryParser, expected: TLSHandshakeType) -> usize {
        // Common
        let tls_type = parser.read_u8();
        assert!(tls_type == TLSMessageType::Handshake as u8);

        let tls_version =  parser.read_u16();
        assert!(tls_version >= 0x0301); // TLS Version 1.0

        let tls_length = parser.read_u16();

        let msg_type = parser.read_u8();
        assert!(msg_type == expected as u8);

        let msg_length = parser.read_u24();
        assert!(msg_length as usize == (tls_length as usize) - 4);

        msg_length as usize
    }

    fn parse_server_hello(&mut self, parser: &mut BinaryParser) {
        let msg_length = self.parse_header(parser, TLSHandshakeType::ServerHello);

        // ServerHello
        let version = parser.read_u16();
        let server_random: Vec<u8> = parser.take(32).iter().cloned().collect();
        self.server_random.extend(server_random);

        let session_size = parser.read_u8() as usize;
        let session: Vec<u8> = parser.take(session_size).iter().cloned().collect();

        self.cipher = parser.read_u16();
        let compression = parser.read_u8();

        assert!(msg_length == 2 + 32 + 1 + session_size + 2 + 1);
    }

    fn parse_certificates(&mut self, parser: &mut BinaryParser) {
        let msg_length = self.parse_header(parser, TLSHandshakeType::Certificate);

        // Payload
        let mut length = parser.read_u24() as usize;

        assert!(length == msg_length - 3);

        while length > 0 {
            let length2 = parser.read_u24() as usize;
            let cert = parser.take(length2).iter().cloned().collect();
            //println!("cert {}", to_hex_string(&cert));

            self.certs.push(X509Certificate::new(cert));

            length -= 3 + length2;
        }

        assert!(length == 0);
    }

    fn parse_server_key_exchange(&mut self, parser: &mut BinaryParser) {
        let msg_length = self.parse_header(parser, TLSHandshakeType::ServerKeyExchange);

        let ecc_params = match self.cipher {
            0xc011 | 0xc012 | 0xc013 | 0xc014 => true,
            _ => false,
        };

        assert!(ecc_params); // XXX

        let pos = parser.tell();

        if ecc_params {
            let point_type = parser.read_u8();
            let named_curve = parser.read_u16();
            let length = parser.read_u8();
            let point: Vec<u8> = parser.take(length as usize).iter().cloned().collect();
        }

        let enc_buf_len = parser.tell() - pos;
        parser.seek(pos);

        let enc_buf: Vec<u8> = parser.take(enc_buf_len).iter().cloned().collect();

        //println!("enc buf {}", to_hex_string(enc_buf.clone()));

        // XXX
        self.signed_blob.extend(self.client_random.clone());
        self.signed_blob.extend(self.server_random.clone());
        self.signed_blob.extend(enc_buf.clone());

        let sig_len = parser.read_u16() as usize;
        let signature: Vec<u8> = parser.take(sig_len).iter().cloned().collect();

        self.signature.extend(signature.clone());

        assert!(msg_length == enc_buf_len + 2 + sig_len);
    }
}

struct BinaryParser<'a> {
    //buf: &'a [u8],
    buf: Vec<u8>,
    idx: usize,
    reader: &'a mut Read,
}

impl<'a> BinaryParser<'a> {
    fn new(reader: &'a mut Read) -> BinaryParser {
        BinaryParser {
            buf: Vec::new(),
            idx: 0,
            reader: reader,
        }
    }

    fn tell(&mut self) -> usize {
        self.idx
    }

    fn seek(&mut self, pos: usize) {
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
    fn take(&mut self, num: usize) -> &[u8] {
        let cur = self.idx;
        self.idx = self.idx + num;

        while self.buf.len() < self.idx {
            self.buffer_up();
        }

        &self.buf[cur .. self.idx]
    }

    fn read_u32(&mut self) -> u32 {
        let raw: &[u8] = self.take(4);

        ((raw[0] as u32) << 24) |
        ((raw[1] as u32) << 16) |
        ((raw[2] as u32) << 8) |
        (raw[3] as u32)
    }

    fn read_u24(&mut self) -> u32 {
        let raw: &[u8] = self.take(3);

        ((raw[0] as u32) << 16) |
        ((raw[1] as u32) << 8) |
        (raw[2] as u32)
    }

    fn read_u16(&mut self) -> u16 {
        let raw: &[u8] = self.take(2);

        ((raw[0] as u16) << 8) |
        (raw[1] as u16)
    }

    fn read_u8(&mut self) -> u8 {
        let raw: &[u8] = self.take(1);

        raw[0]
    }
}



fn perform(server: &String, port: &u16, hash_buf: &[u8; 32], output: &String) {
    let conn_str = format!("{}:{}", server, port);

    //println!("conn_str {}", conn_str);

    let mut tcpconn = TcpStream::connect(&conn_str[..]).unwrap();

    // ClientHello
    let mut client_hello: [u8; 512] = [0; 512];

    // 60 ['\x16\x03\x01\x007\x01\x00\x003\x03\x01foo\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\n\x003\xc0\x11\xc0\x12\xc0\x13\xc0\x14\x01\x00\x00\x00']

    client_hello[0] = 22; // TLS_CONTENT_HANDSHAKE
    client_hello[1] = 0x03; // version
    client_hello[2] = 0x01; // version
    // 3, 4 = length 1
    client_hello[3] = 0x00;
    client_hello[4] = 55;

    client_hello[5] = 0x01; // TLS_HANDSHAKE_CLIENT_HELLO
    // 6,7,8 = length 2
    client_hello[6] = 0;
    client_hello[7] = 0;
    client_hello[8] = 51;

    client_hello[9] = 0x03; // version
    client_hello[10] = 0x01; // version

    for i in 0..32 {
        client_hello[11 + i] = hash_buf[i];
    }

    client_hello[43] = 0;

    // cipher suits
    client_hello[44] = 0x00;
    client_hello[45] = 0x0a;

    client_hello[46] = 0x00; // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    client_hello[47] = 0x33;

    client_hello[48] = 0xc0; // TLS_ECDHE_RSA_WITH_RC4_128_SHA
    client_hello[49] = 0x11;

    client_hello[50] = 0xc0; // TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
    client_hello[51] = 0x12;

    client_hello[52] = 0xc0; // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    client_hello[53] = 0x13;

    client_hello[54] = 0xc0; // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    client_hello[55] = 0x14;

    // compression
    client_hello[56] = 0x01;
    client_hello[57] = 0x00;

    // extensions
    client_hello[58] = 0x00;
    client_hello[59] = 0x00;

    match tcpconn.write(&client_hello[0..60]) {
        Ok(size) => {
            //println!("wrote {} bytes", size);
        }
        Err(_) => {
            panic!("write failure!!!");
        }
    }

    let mut pars = BinaryParser::new(&mut tcpconn);
    let mut tls = TLSHandshake::new();

    // HACK
    tls.client_random.extend(hash_buf[0..32].iter());

    // Parse ServerHello
    tls.parse_server_hello(&mut pars);

    // Parse Certificates
    tls.parse_certificates(&mut pars);

    // Parse ServerKeyExchange
    tls.parse_server_key_exchange(&mut pars);

    // Output
    //for cert in &tls.certs {
    //    println!("cert {}", to_hex_string(cert.buf.clone()));
    //}

    let unix_timestamp = tls.get_unix_timestamp();
    let ts = timestamp_to_datetime(unix_timestamp);
    //println!("{:?} (Unix Timestamp: {})", ts, unix_timestamp);

    //println!("Blob: {}", to_hex_string(tls.signed_blob.clone()));
    //println!("Signature: {}", to_hex_string(tls.signature.clone()));

    let mut obj = BTreeMap::new();
    obj.insert("blob".to_string(), ((&*tls.signed_blob).to_base64(STANDARD)).to_json());
    obj.insert("signature".to_string(), ((&*tls.signature).to_base64(STANDARD)).to_json());

    let mut cert_vec = Vec::new();
    for cert in &tls.certs {
        cert_vec.push(cert.buf.to_base64(STANDARD));
    }
    obj.insert("certificates".to_string(), cert_vec.to_json());

    println!("{}", json::encode(&Json::Object(obj)).ok().expect("json"));

    /*
    {
        let mut f = File::create("data.blob").ok().expect("fail.");
        f.write_all(&*tls.signed_blob);
    }

    {
        let mut f = File::create("data.signature").ok().expect("fail.");
        f.write_all(&*tls.signature);
    }

    {
        let mut f = File::create("data.certificate.der").ok().expect("fail.");
        f.write_all(&*tls.certs[0].buf);
    }
    */
}

fn hash_content<R: Read, D: Digest>(file_handle: &mut R, hasher: &mut D) {
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

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();

    opts.optopt("f", "file", "input file to sign [-]", "PATH");
    opts.optopt("s", "server", "set server for signing [google.com]", "HOSTNAME");
    opts.optopt("p", "port", "set port for --server [443]", "PORT");
    opts.optopt("o", "output", "ouput file [data]", "PATH");

    opts.optflag("h", "help", "print this help menu");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => { m }
        Err(f) => { panic!(f.to_string()) }
    };

    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }

    // parse "output"
    let output = if matches.opt_present("o") {
        matches.opt_str("o").unwrap()
    } else {
        "data".to_string()
    };

    // parse "server"
    let server = if matches.opt_present("s") {
        matches.opt_str("s").unwrap()
    } else {
        "google.com".to_string()
    };

    // parse "port"
    let port: u16 = if matches.opt_present("p") {
        let port_str = matches.opt_str("p").unwrap();
        match port_str.parse() {
            Ok(p) => p,
            Err(_) => {
                print_usage(&program, opts);
                return;
            }
        }
    } else {
        443
    };

    // parse "file" and hash it
    let mut hasher = Sha256::new();

    if matches.opt_present("f") {
        let path = matches.opt_str("f").unwrap();
        let mut file_handle = match File::open(path) {
            Ok(f) => f,
            Err(s) => {
                println!("Reading file failed: {}", s);
                //print_usage(&program, opts);
                return;
            }
        };

        hash_content(&mut file_handle, &mut hasher);
    } else {
        hash_content(&mut io::stdin(), &mut hasher);
    };

    //println!("Hello, world! {} {} {:?}", server, port, hasher.result_str());

    let mut hash_buf: [u8; 32] = [0; 32];
    hasher.result(&mut hash_buf);

    perform(&server, &port, &hash_buf, &output);
}
