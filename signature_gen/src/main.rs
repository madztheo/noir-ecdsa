use num_bigint::BigUint;
use signature::SignerMut;
use std::env;
use toml::Value;

use rand_core::OsRng;
use sha2::{Digest, Sha256};

use p384::{ecdsa::{signature::Signer, Signature, SigningKey}, PublicKey};

use clap::{App, Arg};

use noir_bignum_paramgen::{
    bn_limbs, split_into_120_bit_limbs,
};

fn format_limbs_as_hex(limbs: &Vec<BigUint>) -> String {
    limbs
        .iter()
        .map(|a| format!("0x{:x}", a))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_limbs_as_toml_value(limbs: &Vec<BigUint>) -> Vec<Value> {
    limbs
        .iter()
        .map(|a| Value::String(format!("0x{:x}", a)))
        .collect()
}

fn generate_p384_signature_parameters(msg: &str, as_toml: bool) {
    let mut hasher = Sha256::new();
    hasher.update(msg.as_bytes());
    let hashed_message = hasher.finalize();

    let hashed_as_bytes = hashed_message
        .iter()
        .map(|&b| b.to_string())
        .collect::<Vec<String>>()
        .join(", ");

    let signing_key: SigningKey = SigningKey::random(&mut OsRng);
    let public_key: PublicKey = signing_key.verifying_key().into();
    //let public_key_projective = public_key.to_projective();
    let public_key_bytes = public_key.to_sec1_bytes();
    // The first byte is 04 as defined per SEC1 for uncompressed format
    // The remaining 96 bytes are the x and y coordinates of the public key
    // c.f. https://www.secg.org/sec1-v2.pdf (Section 2.3.3)
    let public_key_x = public_key_bytes[1..49].to_vec();
    let public_key_y = public_key_bytes[49..97].to_vec();
    let (signature, _) = signing_key.sign_prehash_recoverable(&hashed_message).unwrap();
    let (r, s) = signature.split_bytes();

    let r_uint: BigUint = BigUint::from_bytes_be(&r);
    let s_uint: BigUint = BigUint::from_bytes_be(&s);
    let public_key_x_uint: BigUint = BigUint::from_bytes_be(&public_key_x);
    let public_key_y_uint: BigUint = BigUint::from_bytes_be(&public_key_y);

    let r_limbs = bn_limbs(r_uint.clone(), 384);
    let s_limbs = bn_limbs(s_uint.clone(), 384);
    let public_key_x_limbs = bn_limbs(public_key_x_uint.clone(), 384);
    let public_key_y_limbs = bn_limbs(public_key_y_uint.clone(), 384);

    if as_toml {
        let hash_toml = toml::to_vec(&hashed_as_bytes).unwrap();

        let r_limbs = split_into_120_bit_limbs(&r_uint.clone(), 384);
        let s_limbs = split_into_120_bit_limbs(&s_uint.clone(), 384);
        let public_key_x_limbs = split_into_120_bit_limbs(&public_key_x_uint.clone(), 384);
        let public_key_y_limbs = split_into_120_bit_limbs(&public_key_y_uint.clone(), 384);
        let r_toml = Value::Array(format_limbs_as_toml_value(&r_limbs));
        let s_toml = Value::Array(format_limbs_as_toml_value(&s_limbs));
        let public_key_x_toml = Value::Array(format_limbs_as_toml_value(&public_key_x_limbs));
        let public_key_y_toml = Value::Array(format_limbs_as_toml_value(&public_key_y_limbs));

        println!("hash = [{}]", hashed_as_bytes);
        println!("[r]");
        println!("r = {}", r_toml);
        println!("[s]");
        println!("s = {}", s_toml);
        println!("[public_key_x]");
        println!("public_key_x = {}", public_key_x_toml);
        println!("[public_key_y]");
        println!("public_key_y = {}", public_key_y_toml);
    } else {
        println!("let hash: [u8; 32] = [{}];", hashed_as_bytes);
        println!(
            "let r: Secp384r1Fr = Secp384r1Fr::from_array({});",
            r_limbs.as_str()
        );
        println!(
            "let s: Secp384r1Fr = Secp384r1Fr::from_array({});",
            s_limbs.as_str()
        );
        println!(
            "let public_key_x: Secp384r1Fq = Secp384r1Fq::from_array({});",
            public_key_x_limbs.as_str()
        );
        println!(
            "let public_key_y: Secp384r1Fq = Secp384r1Fq::from_array({});",
            public_key_y_limbs.as_str()
        );
    }
}

fn generate_p256_signature_parameters(msg: &str, as_toml: bool) {
    let mut hasher = Sha256::new();
    hasher.update(msg.as_bytes());
    let hashed_message = hasher.finalize();

    let hashed_as_bytes = hashed_message
        .iter()
        .map(|&b| b.to_string())
        .collect::<Vec<String>>()
        .join(", ");

    let signing_key: p256::ecdsa::SigningKey = p256::ecdsa::SigningKey::random(&mut OsRng);
    let public_key: p256::PublicKey = signing_key.verifying_key().into();
    //let public_key_projective = public_key.to_projective();
    let public_key_bytes = public_key.to_sec1_bytes();
    // The first byte is 04 as defined per SEC1 for uncompressed format
    // The remaining 96 bytes are the x and y coordinates of the public key
    // c.f. https://www.secg.org/sec1-v2.pdf (Section 2.3.3)
    let public_key_x = public_key_bytes[1..33].to_vec();
    let public_key_y = public_key_bytes[33..65].to_vec();
    let signature: p256::ecdsa::Signature = signing_key.sign(msg.as_bytes());
    let (r, s) = signature.split_bytes();

    let r_uint: BigUint = BigUint::from_bytes_be(&r);
    let s_uint: BigUint = BigUint::from_bytes_be(&s);
    let public_key_x_uint: BigUint = BigUint::from_bytes_be(&public_key_x);
    let public_key_y_uint: BigUint = BigUint::from_bytes_be(&public_key_y);

    let r_limbs = bn_limbs(r_uint.clone(), 256);
    let s_limbs = bn_limbs(s_uint.clone(), 256);
    let public_key_x_limbs = bn_limbs(public_key_x_uint.clone(), 256);
    let public_key_y_limbs = bn_limbs(public_key_y_uint.clone(), 256);

    if as_toml {
        let hash_toml: Vec<u8> = toml::to_vec(&hashed_as_bytes).unwrap();

        let r_limbs = split_into_120_bit_limbs(&r_uint.clone(), 256);
        let s_limbs = split_into_120_bit_limbs(&s_uint.clone(), 256);
        let public_key_x_limbs = split_into_120_bit_limbs(&public_key_x_uint.clone(), 256);
        let public_key_y_limbs = split_into_120_bit_limbs(&public_key_y_uint.clone(), 256);
        let r_toml = Value::Array(format_limbs_as_toml_value(&r_limbs));
        let s_toml = Value::Array(format_limbs_as_toml_value(&s_limbs));
        let public_key_x_toml = Value::Array(format_limbs_as_toml_value(&public_key_x_limbs));
        let public_key_y_toml = Value::Array(format_limbs_as_toml_value(&public_key_y_limbs));

        println!("hash = [{}]", hashed_as_bytes);
        println!("[r]");
        println!("r = {}", r_toml);
        println!("[s]");
        println!("s = {}", s_toml);
        println!("[public_key_x]");
        println!("public_key_x = {}", public_key_x_toml);
        println!("[public_key_y]");
        println!("public_key_y = {}", public_key_y_toml);
    } else {
        println!("let hash: [u8; 32] = [{}];", hashed_as_bytes);
        println!(
            "let r: Secp256r1Fr = Secp256r1Fr::from_array({});",
            r_limbs.as_str()
        );
        println!(
            "let s: Secp256r1Fr = Secp256r1Fr::from_array({});",
            s_limbs.as_str()
        );
        println!(
            "let public_key_x: Secp256r1Fq = Secp256r1Fq::from_array({});",
            public_key_x_limbs.as_str()
        );
        println!(
            "let public_key_y: Secp256r1Fq = Secp256r1Fq::from_array({});",
            public_key_y_limbs.as_str()
        );
    }
}

fn main() {
    let matches = App::new("ECDSA Signature Generator")
        .arg(
            Arg::with_name("msg")
                .short("m")
                .long("msg")
                .takes_value(true)
                .help("Message to sign")
                .required(true),
        )
        .arg(
            Arg::with_name("toml")
                .short("t")
                .long("toml")
                .help("Print output in TOML format"),
        )
        .arg(
            Arg::with_name("curve")
                .short("c")
                .long("curve")
                .takes_value(true)
                .help("Curve to use (p256 or p384)")
                .default_value("p384")
                .required(true),
        )
        .get_matches();

    let msg = matches.value_of("msg").unwrap();
    let as_toml = matches.is_present("toml");
    let curve = matches.value_of("curve").unwrap();

    if curve == "p256" {
        generate_p256_signature_parameters(msg, as_toml);
    } else if curve == "p384" {
        generate_p384_signature_parameters(msg, as_toml);
    } else {
        println!("Invalid curve specified. Please use 'p256' or 'p384'.");
    }
}
