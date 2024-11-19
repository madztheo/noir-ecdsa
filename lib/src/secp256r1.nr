use bigcurve::curves::secp256r1::{Secp256r1Fr, Secp256r1Fq, SECP256r1_SCALAR_SLICES};
use bigcurve::scalar_field::ScalarField;
use bigcurve::BigCurve;
use bignum::BigNum;
use bigcurve::curves::secp256r1::Secp256r1_Params;

// Set as unconstrained for testing purposes
pub fn verify_secp256r1_ecdsa(
    public_key_x: Secp256r1Fq,
    public_key_y: Secp256r1Fq,
    message_digest: [u8; 32],
    signature: (Secp256r1Fr, Secp256r1Fr),
) -> bool {
    // 1. Unpack the signature (r, s)
    let (r, s): (Secp256r1Fr, Secp256r1Fr) = signature;

    // 2. Convert the message digest to a BigNum
    // There is a chance that the message digest is higher than the field modulus
    let e: Secp256r1Fr = BigNum::from_be_bytes(message_digest);

    // 3. Compute w = s^-1 mod n
    let w = s.__invmod();
    // Check that s is in the inverse of w since the previous line is unconstrained
    assert(s * w == BigNum::one());

    // 4. Compute u1 = ew mod n and u2 = rw mod n
    let u_1: ScalarField<SECP256r1_SCALAR_SLICES> = ScalarField::from_bignum(e * w);
    let u_2: ScalarField<SECP256r1_SCALAR_SLICES> = ScalarField::from_bignum(r * w);

    let public_key = BigCurve { x: public_key_x, y: public_key_y, is_infinity: false };
    public_key.validate_on_curve();

    let gen: BigCurve<Secp256r1Fq, Secp256r1_Params> = BigCurve::one();

    // 5. Compute the point R = u1G + u2Q
    let r_point = BigCurve::msm([gen, public_key], [u_1, u_2]);

    println(f"r: {r}");
    println(f"r_point: {r_point}");
    let r_point_x = r_point.x;
    //println(f"r_point.x: {r_point_x}");
    let r_point_x_as_fr: Secp256r1Fr = BigNum { limbs: r_point_x.limbs };
    // 6. The signature is valid if r = R.x (mod n)
    // Need to have them in the same field to do the comparison
    r_point_x_as_fr == r
}

#[test]
fn test_secp256r1_signature_verification() {
    let sha256_hash: [u8; 32] =
        dep::std::hash::sha256("Hello World! This is Noir-ECDSA".as_bytes());
    assert_eq(
        sha256_hash,
        [
            42, 204, 207, 15, 192, 246, 143, 215, 180, 110, 75, 247, 21, 126, 103, 225, 251, 180,
            86, 221, 251, 68, 216, 63, 17, 236, 32, 223, 169, 198, 9, 98,
        ],
    );
    let r: Secp256r1Fr = BigNum {
        limbs: [0x6e6dd8df9cec8c31892d01e14318fb, 0x3109c73f335657be981f6387c44d3c, 0x8e0e],
    };
    let s: Secp256r1Fr = BigNum {
        limbs: [0x262ed99e46e6577a71a75b1d5c7f4a, 0xcefc34f4b68aa019eda376372f2e76, 0x2c2d],
    };
    let public_key_x: Secp256r1Fq = BigNum {
        limbs: [0xd54378ffd74c0a0692ea56dc91e14a, 0xa683ef4c166c55cfb8d135863fc8f9, 0xaa1d],
    };
    let public_key_y: Secp256r1Fq = BigNum {
        limbs: [0x6b6c3604db3440d3dc4ee95a24f0f0, 0xc4eae722e511eeb583122a0f6ab255, 0x4b36],
    };
    assert(verify_secp256r1_ecdsa(public_key_x, public_key_y, sha256_hash, (r, s)));
}

