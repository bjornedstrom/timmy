extern crate crypto;
extern crate getopts;

use self::crypto::digest::Digest;
use self::crypto::sha2::Sha256;
use getopts::Options;
use std::env;
use std::io;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::net::TcpStream;

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

pub fn to_hex_string(bytes: Vec<u8>) -> String {
    let strs: Vec<String> = bytes.iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    strs.connect("")
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

    fn buffer_up(&mut self) {
        let mut arr: [u8; 4096] = [0; 4096];

        match self.reader.read(&mut arr) {
            Ok(size) => {
                println!("read {} bytes", size);

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

        if self.buf.len() < self.idx {
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



fn perform(server: &String, port: &u16, hash_buf: &[u8; 32]) {
    let conn_str = format!("{}:{}", server, port);

    println!("conn_str {}", conn_str);

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
            println!("wrote {} bytes", size);
        }
        Err(_) => {
            panic!("write failure!!!");
        }
    }

    let mut pars = BinaryParser::new(&mut tcpconn);

    println!("type {:x}", pars.read_u8());
    println!("version {:x}", pars.read_u16());
    println!("length {:x}", pars.read_u16());


    println!("msg_type {:x}", pars.read_u8());
    println!("msg_length {:x}", pars.read_u24());

    println!("version {:x}", pars.read_u16());

    println!("server random {}", to_hex_string(pars.take(32).iter().cloned().collect() ));

    println!("session {}", to_hex_string(pars.take( pars.read_u8() as usize  ).iter().cloned().collect() ));


    /*
    let mut buf: [u8; 16000] = [0; 16000];

    loop {
        match tcpconn.read(&mut buf) {
            Ok(0) => { break }
            Ok(size) => {
                println!("read {} bytes", size);

                let mut pars = BinaryParser { buf: &buf, idx: 0, reader: &mut tcpconn };

                println!("{:x}", pars.read_u32());

                return; // XXX
            }
            // Makes sense?
            Err(_) => { panic!("read failure!!!"); }
        };
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

    opts.optflag("h", "help", "print this help menu");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => { m }
        Err(f) => { panic!(f.to_string()) }
    };

    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }

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

    perform(&server, &port, &hash_buf);
}
