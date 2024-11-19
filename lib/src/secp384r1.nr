// Inspired by https://github.com/noir-lang/noir/blob/21425dedcc31287431a4a25589d52d5397e974bc/noir_stdlib/src/ec/swcurve.nr#L190
use bigcurve::curves::secp384r1::{Secp384r1Fr, Secp384r1Fq, SECP384r1_SCALAR_SLICES};
use bigcurve::scalar_field::ScalarField;
use bigcurve::BigCurve;
use bignum::BigNum;
use bigcurve::curves::secp384r1::Secp384r1_Params;

// Set as unconstrained for testing purposes
pub fn verify_secp384r1_ecdsa(
    public_key_x: Secp384r1Fq,
    public_key_y: Secp384r1Fq,
    message_digest: [u8; 32],
    signature: (Secp384r1Fr, Secp384r1Fr),
) -> bool {
    // 1. Unpack the signature (r, s)
    let (r, s): (Secp384r1Fr, Secp384r1Fr) = signature;

    // 2. Pad the message digest to 48 bytes and convert to a BigNum
    let mut message_digest_padded: [u8; 48] = [0; 48];
    for i in 16..48 {
        message_digest_padded[i] = message_digest[i - 16];
    }
    let e: Secp384r1Fr = BigNum::from_be_bytes(message_digest_padded);

    // 3. Compute w = s^-1 mod n
    let w = s.__invmod();
    // Check that s is in the inverse of w since the previous line is unconstrained
    assert(s * w == BigNum::one());

    // 4. Compute u1 = ew mod n and u2 = rw mod n
    let u_1: ScalarField<SECP384r1_SCALAR_SLICES> = ScalarField::from_bignum(e * w);
    let u_2: ScalarField<SECP384r1_SCALAR_SLICES> = ScalarField::from_bignum(r * w);

    // Convert public key to jacobian coordinates
    let public_key = BigCurve { x: public_key_x, y: public_key_y, is_infinity: false };
    let gen: BigCurve<Secp384r1Fq, Secp384r1_Params> = BigCurve::one();

    // 5. Compute the point R = u1G + u2Q
    let r_point = BigCurve::msm([gen, public_key], [u_1, u_2]);

    println(f"r: {r}");
    println(f"r_point: {r_point}");
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
            0xbf06453c0ea6541331d12352f60d26,
            0x77db270c38cfd184082e3bfaeb919f,
            0x621ecd5b3e0a8110dd4b9959fd8fda,
            0xb0570c,
        ],
    };
    let s: Secp384r1Fr = BigNum {
        limbs: [
            0x8e3affaa88802f9a6452f623b626b1,
            0xdb2a287312a577031ce9f209e84c17,
            0x73bc5f486a545f9c1f19ec6ac8bcfb,
            0xdcbfba,
        ],
    };
    let public_key_x: Secp384r1Fq = BigNum {
        limbs: [
            0x7eaf8f9cc0a55a3ba2ee33c60ffab2,
            0x1c7d48b9789e2721519e903e6b3d66,
            0xfe8be327ca83bd327eeed429c6355b,
            0x23fc3e,
        ],
    };
    let public_key_y: Secp384r1Fq = BigNum {
        limbs: [
            0xa557029ebcac31208fed16f156ee51,
            0xa6110be2e161bfffd42ae464f00dc8,
            0x46b9a9867e6ffa84e4c12190862518,
            0x1cc4a8,
        ],
    };
    assert(verify_secp384r1_ecdsa(public_key_x, public_key_y, sha256_hash, (r, s)));
}

