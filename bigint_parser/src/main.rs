use num_bigint::BigUint;

use clap::{App, Arg};

use noir_bignum_paramgen::bn_limbs;


fn main() {
    let matches = App::new("Big Int Parser")
        .arg(
            Arg::with_name("hex")
                .short("h")
                .long("hex")
                .takes_value(true)
                .help("Hex number to parse")
                .required(true),
        )
        .arg(
            Arg::with_name("bits")
                .short("b")
                .long("bits")
                .takes_value(true)
                .help("Number of bits needed to represent the number")
                .default_value("384")
        )
        .get_matches();

    let mut hex = matches.value_of("hex").unwrap();
    hex = hex.strip_prefix("0x").unwrap_or(hex);
    let bits = matches.value_of("bits").unwrap();
    let bits = bits.parse::<u32>().unwrap();
    
    let hex_bytes = hex::decode(hex).unwrap();
    let big_uint = BigUint::from_bytes_be(hex_bytes.as_slice());
    let limbs = bn_limbs(big_uint, bits as usize);
    println!("Limbs: {:?}", limbs);
}
