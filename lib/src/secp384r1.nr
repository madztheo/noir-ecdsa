use bigcurve::curves::secp384r1::{Secp384r1Fr, Secp384r1Fq, SECP384r1_SCALAR_SLICES};
use bigcurve::scalar_field::ScalarField;
use bigcurve::BigCurve;
use bignum::BigNum;
use bigcurve::curves::secp384r1::Secp384r1_Params;

pub fn verify_secp384r1_ecdsa<let HASH_BYTE_SIZE: u32>(
    public_key_x: Secp384r1Fq,
    public_key_y: Secp384r1Fq,
    message_digest: [u8; HASH_BYTE_SIZE],
    signature: (Secp384r1Fr, Secp384r1Fr),
) -> bool {
    // 1. Unpack the signature (r, s)
    let (r, s): (Secp384r1Fr, Secp384r1Fr) = signature;

    // 2. Pad the message digest to 48 bytes and convert to a BigNum
    let mut formatted_message_digest: [u8; 48] = [0; 48];
    let mut startIndex = 0;
    if HASH_BYTE_SIZE < 48 {
        startIndex = 48 - HASH_BYTE_SIZE;
    }
    for i in startIndex..48 {
        formatted_message_digest[i] = message_digest[i - startIndex];
    }
    let e: Secp384r1Fr = BigNum::from_be_bytes(formatted_message_digest);

    // 3. Compute w = s^-1 mod n
    let w = s.__invmod();
    // Check that s is in the inverse of w since the previous line is unconstrained
    assert(s * w == BigNum::one());

    // 4. Compute u1 = ew mod n and u2 = rw mod n
    let u_1: ScalarField<SECP384r1_SCALAR_SLICES> = ScalarField::from_bignum(e * w);
    let u_2: ScalarField<SECP384r1_SCALAR_SLICES> = ScalarField::from_bignum(r * w);

    // Convert public key to jacobian coordinates
    let public_key = BigCurve { x: public_key_x, y: public_key_y, is_infinity: false };
    public_key.validate_on_curve();

    let gen: BigCurve<Secp384r1Fq, Secp384r1_Params> = BigCurve::one();

    // 5. Compute the point R = u1G + u2Q
    let r_point = BigCurve::msm([gen, public_key], [u_1, u_2]);

    let r_point_x = r_point.x;
    let r_point_x_as_fr: Secp384r1Fr = BigNum { limbs: r_point_x.limbs };
    // 6. The signature is valid if r = R.x (mod n)
    // Need to have them in the same field to do the comparison
    r_point_x_as_fr == r
}

#[test]
fn test_secp384r1_signature_verification() {
    let sha256_hash: [u8; 32] =
        dep::std::hash::sha256("Hello World! This is Noir-ECDSA".as_bytes());
    assert_eq(
        sha256_hash,
        [
            42, 204, 207, 15, 192, 246, 143, 215, 180, 110, 75, 247, 21, 126, 103, 225, 251, 180,
            86, 221, 251, 68, 216, 63, 17, 236, 32, 223, 169, 198, 9, 98,
        ],
    );
    let r: Secp384r1Fr = BigNum {
        limbs: [
            0xeb06adc631cd09d17ed3268f65e288,
            0x4102680df5a59b6fc9f8f38cd01016,
            0x272042bb400a185ba04fefaa7c05ce,
            0x680dc4,
        ],
    };
    let s: Secp384r1Fr = BigNum {
        limbs: [
            0x711084a23ae842fc0e6702c3009784,
            0xe17e64a3c451466091c4c1aae7550f,
            0x017a18c55fc11347e0f27fa8fdb958,
            0x32ec1b,
        ],
    };
    let public_key_x: Secp384r1Fq = BigNum {
        limbs: [
            0x4bb414953ec1391fdbc6ea75e0d61a,
            0xfed1f2c9f9ac404d4bf5c0b267cddb,
            0xd1031dd17188527bc28ade5c97d23c,
            0x41b3d3,
        ],
    };
    let public_key_y: Secp384r1Fq = BigNum {
        limbs: [
            0x23db4726c61ec970c07ff770a2b380,
            0x3270662d9105998b8e26e9575147da,
            0x33e912de6612af790c627629f33de0,
            0x4b834d,
        ],
    };
    assert(verify_secp384r1_ecdsa(public_key_x, public_key_y, sha256_hash, (r, s)));
}

