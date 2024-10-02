use std::hash::Hash;

use num_bigint::BigUint;

use clap::{App, Arg};
use ark_ec::{hashing::{curve_maps::{swu::SWUMap, wb::WBMap}, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve}, AffineRepr, CurveGroup, Group, VariableBaseMSM};
use ark_ff::{field_hashers::DefaultFieldHasher, Field, PrimeField};
use ark_bls12_381::{G1Projective as G, G1Affine as GAffine, Fr as ScalarField};
use ark_std::{Zero, UniformRand};
use sha2::{Digest, Sha256};
use p384::elliptic_curve::{generic_array::{typenum::U48, GenericArray}, hash2curve::{ExpandMsgXmd, GroupDigest}};
use noir_bignum_paramgen::bn_limbs;

fn main() {
    let matches = App::new("Hash to Curve")
        .arg(
            Arg::with_name("msg")
                .short("m")
                .long("msg")
                .takes_value(true)
                .help("Message to hash")
                .required(true),
        )
        .arg(
            Arg::with_name("curve")
                .short("c")
                .long("curve")
                .takes_value(true)
                .help("Curve to use")
                .default_value("secp384r1")
        )
        .get_matches();

    let msg = matches.value_of("msg").unwrap();
    let curve = matches.value_of("curve").unwrap();

    let msg_bytes = msg.as_bytes();

    if curve == "secp384r1" {
        let result = p384::NistP384::hash_from_bytes::<p384::elliptic_curve::hash2curve::ExpandMsgXmd<Sha256>>(&[&msg_bytes], &[b"CURVE_XMD:SHA-256_SSWU_RO_"]).unwrap();
        println!("resulting ecc point: {:?}", result);
    } else if curve == "bls12-381" {
        let hasher = MapToCurveBasedHasher::<G, DefaultFieldHasher<Sha256>, WBMap<ark_bls12_381::g1::Config>>::new(&[1])
            .expect("Failed to create hasher");
        let hash_result = hasher.hash(&msg_bytes).expect("fail to hash the string to curve");
        println!("resulting ecc point: {:?}", hash_result);
    } else if curve == "secp256r1" {
        let result = p256::NistP256::hash_from_bytes::<p256::elliptic_curve::hash2curve::ExpandMsgXmd<Sha256>>(&[&msg_bytes], &[b"CURVE_XMD:SHA-256_SSWU_RO_"]).unwrap();
        println!("resulting ecc point: {:?}", result);
    } else {
        panic!("Unsupported curve");
    }
}
