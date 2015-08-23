// Copyright (c) Björn Edström <be@bjrn.se> 2015.
// See LICENSE for details.

extern crate chrono;
extern crate crypto;
extern crate getopts;
extern crate num;
extern crate rustc_serialize;

mod timmy;

use chrono::datetime::DateTime;
use chrono::offset::utc::UTC;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use getopts::Options;
use num::bigint::BigUint;
use rustc_serialize::base64::{STANDARD, ToBase64, FromBase64};
use rustc_serialize::json::{self};
use std::env;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::io;
use std::net::TcpStream;

use timmy::rsa::*;
use timmy::util::*;
use timmy::tls::*;
use timmy::x509::*;

macro_rules! println_stderr(
    ($($arg:tt)*) => (
        match writeln!(&mut ::std::io::stderr(), $($arg)* ) {
            Ok(_) => {},
            Err(x) => panic!("Unable to write to stderr: {}", x),
        }
    )
);



#[derive(RustcDecodable, RustcEncodable, Debug)]
struct JsonOutput {
    blob: String,
    certificates: Vec<String>,
    signature: String
}


fn verify(blob: &Vec<u8>, cert0: &Vec<u8>, signature: &Vec<u8>) {

    let cert = X509Certificate::new(cert0.clone());

    let parsed = cert.parse().unwrap(); // XXX unwrap

    let utc_now: DateTime<UTC> = UTC::now();

    let cert_still_valid = utc_now >= parsed.validity.0 && utc_now <= parsed.validity.1;

    if !cert_still_valid {
        println_stderr!("ERROR! Signature verification FAILURE: Certificate has expired.");
        return;
    }

    //println!("{:?}", parsed);

    match parsed.key {
        PublicKey::RSA(rsa_n, rsa_e) => {

            let signature_int = BigUint::from_bytes_be(&signature);
            let sig_op = rsa_encrypt(&signature_int, &rsa_e,  &rsa_n);

            // Account for missing leading 0x00
            let mut raw_pkcs1_ = sig_op.to_bytes_be();
            raw_pkcs1_.insert(0, 0x00);
            let raw_pkcs1 = raw_pkcs1_;

            //println!("{}", estimate_bit_size(&rsa_n));

            // the hash here in the PKCS1 structure is MD5(blob) || SHA1(blob)
            // recall that the first part of blob is the SHA-256 hash
            //println!("{:?}", to_hex_string(&raw_pkcs1));

            // construct our own signature to compare against
            let tls_hash = weird_tls_hash(&blob);
            let constructed_pkcs1 = make_pkcs1_sig_padding(&rsa_n, &tls_hash);

            //println!("{:?}", to_hex_string(&tls_hash));
            //println!("{:?}", to_hex_string(&constructed_pkcs1));

            let valid_signature = crypto_compare(&constructed_pkcs1, &raw_pkcs1);
            //println!("{:?}", valid_signature);

            if valid_signature {
                let mut tls = TLSHandshake::new();
                tls.client_random = blob[0..32].iter().cloned().collect();
                tls.server_random = blob[32..64].iter().cloned().collect();
                let unix_timestamp = tls.get_unix_timestamp();
                let ts = timestamp_to_datetime(unix_timestamp);

                let valid_dates = ts >= parsed.validity.0 && ts <= parsed.validity.1;

                if valid_dates {
                    println!("Signature verification SUCCESS.");
                    println!("Warning! Signature only verified against first X509 certificate.");
                    println!("Please verify yourself that the certificate chain is valid.");
                    println!("");
                    println!("{} Signed SHA-256 {} at {:?} (Unix Timestamp: {})",
                             parsed.subject,
                             to_hex_string(&tls.client_random), ts, unix_timestamp);
                } else {
                    println!("ERROR! Signature verification FAILURE: Invalid timestamp.");
                }

            } else {
                println!("ERROR! Signature verification FAILURE.");
            }
        }
    }

}


fn perform(server: &String, port: &u16, hash_buf: &[u8; 32]) {
    let conn_str = format!("{}:{}", server, port);

    //println!("conn_str {}", conn_str);

    let mut tcpconn = TcpStream::connect(&conn_str[..]).unwrap();

    // Construct our special ClientHello message
    let mut ch = SimpleBinaryWriter::new();
    create_special_client_hello(&mut ch, &hash_buf);

    match tcpconn.write(&ch.buf) {
        Err(_) => {
            panic!("write failure!!!");
        }
        Ok(_) => {}
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

    let utc_now: DateTime<UTC> = UTC::now();
    let utc_now_ts = utc_now.timestamp() as u32;

    //println!("{} {}", utc_now_ts, unix_timestamp);

    if unix_timestamp < utc_now_ts - 3600 || unix_timestamp > utc_now_ts + 3600 {
        println_stderr!("ERROR! Server responded with invalid time! Aborting.");
        return;
    }

    println_stderr!("{} signed SHA-256 {} at {:?} (Unix Timestamp: {})",
                    server, to_hex_string(&hash_buf[0..32].iter().cloned().collect()), ts, unix_timestamp);

    //println!("Blob: {}", to_hex_string(tls.signed_blob.clone()));
    //println!("Signature: {}", to_hex_string(tls.signature.clone()));

    let json_output = JsonOutput {
        blob: tls.signed_blob.to_base64(STANDARD),
        signature: tls.signature.to_base64(STANDARD),
        certificates: tls.certs.iter().map(
            |c| c.buf.to_base64(STANDARD)
            ).collect(),
    };

    println!("{}", json::encode(&json_output).unwrap());
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

    opts.optopt("v", "verify", "verify signature object", "PATH");
    opts.optopt("f", "file", "input file to sign [-]", "PATH");
    opts.optopt("s", "server", "set server for signing [www.google.com]", "HOSTNAME");
    opts.optopt("p", "port", "set port for --server [443]", "PORT");
    //opts.optopt("o", "output", "ouput file [data]", "PATH");

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
    /*let output = if matches.opt_present("o") {
        matches.opt_str("o").unwrap()
    } else {
        "data".to_string()
    };*/

    // parse "server"
    let server = if matches.opt_present("s") {
        matches.opt_str("s").unwrap()
    } else {
        "www.google.com".to_string()
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

    if !matches.opt_present("v") {
        // sign

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
    } else {
        // verify

        let path = matches.opt_str("v").unwrap();
        let mut contents: Vec<u8> = Vec::new();
        let file_handle = File::open(path) ;
        file_handle.unwrap().read_to_end(&mut contents).unwrap();

        let filestr = String::from_utf8(contents).unwrap();

        let json_blob: JsonOutput = json::decode(&filestr).unwrap();

        //println!("{:?}", json_blob);

        let blob = json_blob.blob.from_base64().unwrap();
        let cert0 = json_blob.certificates[0].from_base64().unwrap();
        let signature = json_blob.signature.from_base64().unwrap();

        verify(&blob, &cert0, &signature);
    }
}
