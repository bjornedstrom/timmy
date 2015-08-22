//! X509 certificate parsing

use chrono::*;
use num::bigint::BigUint;
use std::fmt::Write as FmtWrite;

use timmy::asn1::*;
use timmy::tup::*;

#[derive(Debug)]
pub enum X509Error {
    InvalidType(String),
    InvalidSequence(String),
    InvalidTimestamp(String),
    InvalidPublicKey(String),
}

pub type X509Result<T> = Result<T, X509Error>;

fn x509_oid_to_str(oid: &ASN1Type) -> String {
    let ret = match oid {
        &ASN1Type::Object(Tup::T4(2, 5, 4, 6)) => "C",
        &ASN1Type::Object(Tup::T4(2, 5, 4, 8)) => "ST",
        &ASN1Type::Object(Tup::T4(2, 5, 4, 7)) => "L",
        &ASN1Type::Object(Tup::T4(2, 5, 4, 10)) => "O",
        &ASN1Type::Object(Tup::T4(2, 5, 4, 3)) => "CN",
        _ => "unknown"
    };

    ret.to_string()
}

pub fn x509_subject_to_string(subject: &ASN1Type) -> X509Result<String> {
    let mut result_string = "".to_string();

    match subject {
        &ASN1Type::Sequence(ref parts) => {
            for ent in &*parts {
                if let &ASN1Type::Set(ref seq) = ent {
                    //println!("{:?}", seq[0]);

                    let ref seq0 = seq[0];
                    if let ASN1Type::Sequence(ref obj_str) = *seq0 {

                        let oid_str = x509_oid_to_str(&obj_str[0]);
                        if let Some(value) = asn1_to_raw_string(&obj_str[1]) {
                            write!(&mut result_string, "{}={}/", oid_str, value).unwrap();
                        }
                    }
                }
            }
        }
        _ => {}
    }

    Ok(result_string)
}

pub fn x509_validity_to_datetime(validity: &ASN1Type) -> X509Result<(DateTime<UTC>, DateTime<UTC>)> {
    if let &ASN1Type::Sequence(ref two_dates) = validity {
        if two_dates.len() != 2 {
            return Err(X509Error::InvalidSequence(
                "TBSCertificate.validity should contain 2 items".to_string()));
        }

        let ref first = two_dates[0];
        let ref last = two_dates[1];

        match (first, last) {
            (&ASN1Type::UTCTime(ref dt1_str), &ASN1Type::UTCTime(ref dt2_str)) => {
                let dt1 = UTC.datetime_from_str(&dt1_str, "%y%m%d%H%M%SZ");
                let dt2 = UTC.datetime_from_str(&dt2_str, "%y%m%d%H%M%SZ");

                match (dt1, dt2) {
                    (Ok(a), Ok(b)) => Ok((a, b)),
                    _ => Err(X509Error::InvalidTimestamp(
                        format!("TBSCertificate.validity are on the wrong format: {:?} {:?}",
                                dt1_str, dt2_str)))
                }
            }
            _ => { Err(X509Error::InvalidSequence(
                format!("TBSCertificate.validity has invalid types: {:?} {:?}",
                        first, last))) }
        }

    } else {
        Err(X509Error::InvalidType(
            "TBSCertificate.validity should be a sequence".to_string()))
    }
}

#[derive(Debug)]
pub enum AlgorithmIdentifier {
    Unsupported,
    RSA
}

fn x509_parse_algorithm_identifier(ai: &ASN1Type) -> X509Result<AlgorithmIdentifier> {
    match ai {
        &ASN1Type::Sequence(ref seq) => {
            if seq.len() < 2 {
                return Err(X509Error::InvalidSequence(
                    "AlgorithmIdentifier should contain 2 items".to_string()));
            }

            let ref algo = seq[0];

            Ok(match *algo {
                ASN1Type::Object(Tup::T7(1, 2, 840, 113549, 1, 1, 1)) => AlgorithmIdentifier::RSA,
                _ => AlgorithmIdentifier::Unsupported
            })
        }
        _ => Err(X509Error::InvalidType(
            "AlgorithmIdentifier should be a sequence".to_string()))
    }
}

#[derive(Debug)]
pub enum PublicKey {
    RSA(BigUint, BigUint) // n, e
}

pub fn x509_parse_public_key_info(info: &ASN1Type) -> X509Result<PublicKey> {
    if let &ASN1Type::Sequence(ref algo_pubkey) = info {
        let ref algo_seq = algo_pubkey[0];
        let ref pubkey = algo_pubkey[1];

        let ai = try!(x509_parse_algorithm_identifier(algo_seq));

        if let &ASN1Type::BitString(ref bitstring) = pubkey {
            // TODO (bjorn): Fix this parsing, not super reliable.
            let mut derparser = DerParser::new(&bitstring[1..].iter().cloned().collect());
            let bs_tree = derparser.parse_entry();

            //println!("bitstring: {:?}", bs_tree)
            if let ASN1Type::Sequence(ref pk_seq) = bs_tree.expect("TODO") {
                match ai {
                    AlgorithmIdentifier::RSA => {
                        let rsa_n = asn1_to_raw_integer(&pk_seq[0]).expect("TODO");
                        let rsa_e = asn1_to_raw_integer(&pk_seq[1]).expect("TODO");

                        Ok(PublicKey::RSA(rsa_n.to_biguint().expect("TODO"),
                                          rsa_e.to_biguint().expect("TODO")))
                    },
                    _ => Err(X509Error::InvalidPublicKey(
                        "Only RSA is supported".to_string()))
                }
            } else {
                Err(X509Error::InvalidType(
                    "public key material should be a sequence".to_string()))
            }
        } else {
            Err(X509Error::InvalidType(
                "SubjectPublicKeyInfo.subjectPublicKey should be a BitString".to_string()))
        }
    } else {
        Err(X509Error::InvalidType(
            "SubjectPublicKeyInfo should be a sequence".to_string()))
    }
}

#[derive(Debug)]
pub struct ParsedX509Certificate {
    pub key: PublicKey,
    pub validity: (DateTime<UTC>, DateTime<UTC>),
    pub subject: String,
}

pub struct X509Certificate {
    pub buf: Vec<u8>,
}

impl X509Certificate {
    pub fn new(der: Vec<u8>) -> X509Certificate {
        X509Certificate {
            buf: der,
        }
    }

    pub fn parse(&self) -> X509Result<ParsedX509Certificate> {
        let mut derparser = DerParser::new(&self.buf);

        let asn1tree = derparser.parse_entry();
        let tree = asn1tree.expect("...");

        // Slice patterns are experimental right now, so lets do this
        // awkwardly.
        match tree {
            ASN1Type::Sequence(body) => {
                match body[0] {
                    ASN1Type::Sequence(ref part0) => {
                        //for ent in &*part0 {
                        //    println!("seq {:?}", ent);
                        //}

                        let ref tbs = *part0;

                        //let ref version = tbs[0];
                        //let ref serialNumber = tbs[1];
                        //let ref signature = tbs[2];
                        //let ref issuer = tbs[3];
                        let ref validity = tbs[4];
                        let ref subject = tbs[5];
                        let ref subject_public_key_info = tbs[6];


                        let field_subject = try!(x509_subject_to_string(subject));
                        let field_validity = try!(x509_validity_to_datetime(validity));
                        let field_public_key = try!(x509_parse_public_key_info(subject_public_key_info));

                        let fields = ParsedX509Certificate {
                            key: field_public_key,
                            validity: field_validity,
                            subject: field_subject,
                        };

                        //self.fields = Some(fields);

                        Ok(fields)

                        //println!("{:?}", *subject);
                        //println!("{}", x509_subject_to_string(subject));
                        //println!("{:?}", x509_validity_to_datetime(validity));
                        //println!("{:?}", x509_parse_public_key_info(subjectPublicKeyInfo));
                    }
                    _ => {
                        Err(X509Error::InvalidType(
                            "certificate should be a sequence".to_string()))
                    }
                }
            }
            _ => {
                Err(X509Error::InvalidType(
                    "certificate should be a sequence".to_string()))
            }
        }
    }
}
