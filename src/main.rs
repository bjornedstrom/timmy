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
use std::process::exit;

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

fn verify(blob: &Vec<u8>, cert0: &Vec<u8>, signature: &Vec<u8>) -> i32 {
    // Parse certificates
    let cert = X509Certificate::new(cert0.clone());
    let parsed_cert = match cert.parse() {
        Ok(cert) => cert,
        Err(e) => {
            println_stderr!("ERROR! Failed to parse certificate: {:?}", e);
            return 1;
        }
    };

    // Check if certificate expired.
    let utc_now: DateTime<UTC> = UTC::now();
    let cert_still_valid = utc_now >= parsed_cert.validity.0 && utc_now <= parsed_cert.validity.1;
    if !cert_still_valid {
        println_stderr!("ERROR! Signature verification FAILURE: Certificate has expired.");
        return 1;
    }

    match parsed_cert.key {
        PublicKey::RSA(rsa_n, rsa_e) => {

            // Perform RSA signature operation
            let signature_int = BigUint::from_bytes_be(&signature);
            let sig_op = rsa_encrypt(&signature_int, &rsa_e,  &rsa_n);

            // Fix up PKCS1.5 blob
            let mut raw_pkcs1_ = sig_op.to_bytes_be();
            raw_pkcs1_.insert(0, 0x00);
            let raw_pkcs1 = raw_pkcs1_;

            // Construct our own PKCS 1.5 blob to compare against
            let tls_hash = weird_tls_hash(&blob);
            let constructed_pkcs1 = make_pkcs1_sig_padding(&rsa_n, &tls_hash);

            let valid_signature = crypto_compare(&constructed_pkcs1, &raw_pkcs1);

            if valid_signature {
                // Signature is valid, parse out fields from blob.
                let mut tls = TLSHandshake::new();
                tls.client_random = blob[0..32].iter().cloned().collect();
                tls.server_random = blob[32..64].iter().cloned().collect();

                // Validate signed timestamp against certificate validity period.
                let unix_timestamp = tls.get_unix_timestamp();
                let ts = timestamp_to_datetime(unix_timestamp);
                let valid_dates = ts >= parsed_cert.validity.0 && ts <= parsed_cert.validity.1;

                if valid_dates {
                    // Success!
                    println!("Signature verification SUCCESS.");
                    println!("Warning! Signature only verified against first X509 certificate.");
                    println!("Please verify yourself that the certificate chain is valid.");
                    println!("");
                    println!("{} Signed SHA-256 {} at {:?} (Unix Timestamp: {})",
                             parsed_cert.subject,
                             to_hex_string(&tls.client_random), ts, unix_timestamp);
                } else {
                    println!("ERROR! Signature verification FAILURE: Invalid timestamp.");
                    return 1;
                }

            } else {
                println!("ERROR! Signature verification FAILURE.");
                return 1;
            }
        }
    }

    0
}

fn sign(server: &String, port: &u16, hash_buf: &[u8; 32]) -> i32 {
    // Construct our special ClientHello message and send it to the server.
    let conn_str = format!("{}:{}", server, port);
    let mut tcpconn = match TcpStream::connect(&conn_str[..]) {
        Ok(conn) => conn,
        Err(err) => {
            println_stderr!("ERROR! Failed to connect to server: {}", err);
            return 1;
        }
    };

    let mut ch = SimpleBinaryWriter::new();
    create_special_client_hello(&mut ch, &hash_buf);

    match tcpconn.write(&ch.buf) {
        Err(_) => {
            println_stderr!("ERROR! Failed to write to server.");
            return 1;
        }
        Ok(_) => {}
    }

    // Parse the response.
    let mut pars = BinaryParser::new(&mut tcpconn);
    let mut tls = TLSHandshake::new();

    tls.client_random.extend(hash_buf[0..32].iter());

    tls.parse_server_hello(&mut pars);
    tls.parse_certificates(&mut pars);
    tls.parse_server_key_exchange(&mut pars);

    // Extract timestamp and perform checks on it.
    let unix_timestamp = tls.get_unix_timestamp();
    let ts = timestamp_to_datetime(unix_timestamp);

    let utc_now: DateTime<UTC> = UTC::now();
    let utc_now_ts = utc_now.timestamp() as u32;

    if unix_timestamp < utc_now_ts - 3600 || unix_timestamp > utc_now_ts + 3600 {
        println_stderr!("ERROR! Server responded with invalid time! Aborting.");
        return 1;
    }

    // Output banner and result JSON blob.
    println_stderr!("{} signed SHA-256 {} at {:?} (Unix Timestamp: {})",
                    server, to_hex_string(&hash_buf[0..32].iter().cloned().collect()), ts, unix_timestamp);

    let json_output = JsonOutput {
        blob: tls.signed_blob.to_base64(STANDARD),
        signature: tls.signature.to_base64(STANDARD),
        certificates: tls.certs.iter().map(
            |c| c.buf.to_base64(STANDARD)
            ).collect(),
    };

    match json::encode(&json_output) {
        Ok(json) => {
            println!("{}", json);
        },
        Err(_) => {
            println_stderr!("ERROR! Failed to serialize json.");
            return 1;
        }
    }

    0
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();

    opts.optopt("V", "verify", "verify signature object", "PATH");
    opts.optopt("S", "sign", "input file to sign [-]", "PATH");
    opts.optopt("H", "host", "set server for signing [www.google.com]", "HOSTNAME");
    opts.optopt("p", "port", "set port for --server [443]", "PORT");

    opts.optflag("h", "help", "print this help menu");

    let parse_result = opts.parse(&args[1..]);

    if let Err(f) = parse_result {
        println_stderr!("ERROR: {}", f.to_string());
        return;
    }

    let matches = parse_result.unwrap();

    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }

    // parse "host"
    let server = if matches.opt_present("H") {
        matches.opt_str("H").unwrap()
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

    if !matches.opt_present("V") {
        // sign

        // parse "file" and hash it
        let mut hasher = Sha256::new();

        if matches.opt_present("S") {
            let path = matches.opt_str("S").unwrap();
            let mut file_handle = match File::open(path) {
                Ok(f) => f,
                Err(s) => {
                    println_stderr!("Reading file failed: {}", s);
                    exit(1);
                }
            };

            hash_content(&mut file_handle, &mut hasher);
        } else {
            hash_content(&mut io::stdin(), &mut hasher);
        };

        let mut hash_buf: [u8; 32] = [0; 32];
        hasher.result(&mut hash_buf);

        let ret = sign(&server, &port, &hash_buf);

        exit(ret);
    } else {
        // verify

        let path = matches.opt_str("V").unwrap();
        let mut contents: Vec<u8> = Vec::new();

        let mut file_handle = match File::open(path) {
                Ok(f) => f,
                Err(s) => {
                    println_stderr!("Reading file failed: {}", s);
                    exit(1);
                }
            };

        match file_handle.read_to_end(&mut contents) {
            Err(s) => {
                println_stderr!("Reading file failed: {}", s);
                exit(1);
            }
            Ok(_) => {}
        }

        let filestr = String::from_utf8(contents).unwrap();

        let json_blob: JsonOutput = match json::decode(&filestr) {
            Ok(json) => { json },
            Err(_) => {
                println_stderr!("ERROR! Failed to deserialize json.");
                exit(1);
            }
        };

        let blob = match json_blob.blob.from_base64() {
            Ok(res) => { res },
            Err(_) => {
                println_stderr!("ERROR! Failed to decode base64 for: blob");
                exit(1);
            }
        };

        let cert0 = match json_blob.certificates[0].from_base64() {
            Ok(res) => { res },
            Err(_) => {
                println_stderr!("ERROR! Failed to decode base64 for: certificates[0]");
                exit(1);
            }
        };

        let signature = match json_blob.signature.from_base64() {
            Ok(res) => { res },
            Err(_) => {
                println_stderr!("ERROR! Failed to decode base64 for: signature");
                exit(1);
            }
        };

        let ret = verify(&blob, &cert0, &signature);

        exit(ret);
    }
}
