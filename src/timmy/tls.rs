//! TLS related code.

use crypto::digest::Digest;
use crypto::md5::Md5;
use crypto::sha1::Sha1;

use timmy::util::*;
use timmy::x509::*;

pub type TLSResult<T> = Result<T, String>;

pub enum TLSMessageType {
    Alert = 21,
    Handshake = 22,
}

pub enum TLSHandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    Certificate = 11,
    ServerKeyExchange = 12,
}

pub struct TLSHandshake {
    pub client_random: Vec<u8>,
    pub server_random: Vec<u8>,
    pub certs: Vec<X509Certificate>,
    cipher: u16,
    pub signed_blob: Vec<u8>,
    pub signature: Vec<u8>,
}

impl TLSHandshake {
    pub fn new() -> TLSHandshake {
        TLSHandshake {
            client_random: Vec::new(),
            server_random: Vec::new(),
            certs: Vec::new(),
            cipher: 0,
            signed_blob: Vec::new(),
            signature: Vec::new(),
        }
    }

    /*fn get_signature(&self) -> &Vec<u8> {
        &self.signature
    }*/

    pub fn get_unix_timestamp(&self) -> u32 {
        let raw = &self.server_random;

        ((raw[0] as u32) << 24) |
        ((raw[1] as u32) << 16) |
        ((raw[2] as u32) << 8) |
        (raw[3] as u32)
    }

    fn handle_alert(&mut self, parser: &mut BinaryParser, tls_type: u8) -> TLSResult<usize> {
        if tls_type != TLSMessageType::Alert as u8 {
            return Err("TLS error: Malformed protocol. Is this really a TLS server?".to_string())
        }

        assert!(tls_type == TLSMessageType::Alert as u8);

        let _ = parser.read_u16(); // version
        let _ = parser.read_u16(); // length

        let level = parser.read_u8();
        assert!(level >= 1 && level <= 2);

        let description = parser.read_u8();

        let level_str = match level {
            1 => "WARNING",
            2 => "FATAL",
            _ => unreachable!(),
        };

        Err(format!("TLS error: most likely the server does not support the necessary signing behavior. (Alert: {}({}))", level_str, description))
    }

    fn parse_header(&mut self, parser: &mut BinaryParser, expected: TLSHandshakeType) -> TLSResult<usize> {
        // Common
        let tls_type = parser.read_u8();
        if tls_type != TLSMessageType::Handshake as u8 {
            try!(self.handle_alert(parser, tls_type));
        }
        assert!(tls_type == TLSMessageType::Handshake as u8);

        let tls_version =  parser.read_u16();
        assert!(tls_version >= 0x0301); // TLS Version 1.0

        let tls_length = parser.read_u16();

        let msg_type = parser.read_u8();
        assert!(msg_type == expected as u8);

        let msg_length = parser.read_u24();
        assert!(msg_length as usize == (tls_length as usize) - 4);

        Ok(msg_length as usize)
    }

    pub fn parse_server_hello(&mut self, parser: &mut BinaryParser) -> TLSResult<()> {
        let msg_length = try!(self.parse_header(parser, TLSHandshakeType::ServerHello));

        // ServerHello
        let _ /*version*/ = parser.read_u16();
        let server_random: Vec<u8> = parser.take(32).iter().cloned().collect();
        self.server_random.extend(server_random);

        let session_size = parser.read_u8() as usize;
        let _ /*session*/: Vec<u8> = parser.take(session_size).iter().cloned().collect();

        self.cipher = parser.read_u16();
        let _ /*compression*/ = parser.read_u8();

        assert!(msg_length == 2 + 32 + 1 + session_size + 2 + 1);

        Ok(())
    }

    pub fn parse_certificates(&mut self, parser: &mut BinaryParser) -> TLSResult<()> {
        let msg_length = try!(self.parse_header(parser, TLSHandshakeType::Certificate));

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

        Ok(())
    }

    pub fn parse_server_key_exchange(&mut self, parser: &mut BinaryParser) -> TLSResult<()> {
        let msg_length = try!(self.parse_header(parser, TLSHandshakeType::ServerKeyExchange));

        let ecc_params = match self.cipher {
            0xc011 | 0xc012 | 0xc013 | 0xc014 => true,
            _ => false,
        };

        assert!(ecc_params); // XXX

        let pos = parser.tell();

        if ecc_params {
            let _ /*point_type*/ = parser.read_u8();
            let _ /*named_curve*/ = parser.read_u16();
            let length = parser.read_u8();
            let _ /*point*/: Vec<u8> = parser.take(length as usize).iter().cloned().collect();
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

        Ok(())
    }

    pub fn parse(&mut self, parser: &mut BinaryParser) -> TLSResult<()> {
        try!(self.parse_server_hello(parser));
        try!(self.parse_certificates(parser));
        try!(self.parse_server_key_exchange(parser));

        Ok(())
    }
}

pub fn create_special_client_hello(ch: &mut SimpleBinaryWriter, hash_buf: &[u8; 32]) {
    ch.put_u8(TLSMessageType::Handshake as u8);
    ch.put_u16(0x0301);
    ch.put_u16(0); // Length 1
    ch.put_u8(TLSHandshakeType::ClientHello as u8);
    ch.put_u24(0); // Length 2
    ch.put_u16(0x0301);
    ch.buf.extend(&hash_buf[0..32]);
    ch.put_u8(0);

    // cipher suits
    let cipher_suits = vec![
        0x0033,
        0xc011,
        0xc012,
        0xc013,
        0xc014,
        ];
    ch.put_u16((cipher_suits.len() * 2) as u16); // 5 * 2
    for cipher in &cipher_suits {
        ch.put_u16(*cipher);
    }

    // Compression
    ch.put_u8(1);
    ch.put_u8(0x00);

    // Extensions
    ch.put_u16(0);

    // HACK: fixup length fields
    let size = ch.buf.len();
    ch.buf[4] = (size - 5) as u8; // only works if size < one byte
    ch.buf[8] = (size - 9) as u8;
}

pub fn weird_tls_hash(blob: &Vec<u8>) -> Vec<u8> {
    let mut hash_sha1 = Sha1::new();
    let mut hash_md5 = Md5::new();

    hash_sha1.input(&blob);
    hash_md5.input(&blob);

    let mut hash_result: [u8; 36] = [0; 36];
    hash_md5.result(&mut hash_result[0..16]);
    hash_sha1.result(&mut hash_result[16..36]);

    hash_result.iter().cloned().collect()
}
