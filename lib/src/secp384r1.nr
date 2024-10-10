// Inspired by https://github.com/noir-lang/noir/blob/21425dedcc31287431a4a25589d52d5397e974bc/noir_stdlib/src/ec/swcurve.nr#L190
use dep::bignum::BigNum;
use dep::bignum::BigNumTrait;
use dep::bignum::fields::secp384r1Fq::Secp384r1_Fq_Params;
use dep::bignum::fields::secp384r1Fr::Secp384r1_Fr_Params;

use dep::bigcurve::BigCurve;
use dep::bigcurve::CurveParamsTrait;

use dep::bigcurve::curve_jac;
use dep::bigcurve::curve_jac::JTranscript;
use dep::bigcurve::curve_jac::AffineTranscript;
use dep::bigcurve::curve_jac::CurveJ;
use dep::bigcurve::scalar_field::ScalarField;
use dep::bigcurve::PointTable;

type Secp384r1Fq = BigNum<4, Secp384r1_Fq_Params>;
type Secp384r1Fr = BigNum<4, Secp384r1_Fr_Params>;

struct Secp384r1Params{}

impl CurveParamsTrait<Secp384r1Fq> for Secp384r1Params {
    fn one() -> [Secp384r1Fq; 2] {
        let mut one: Secp384r1Fq = BigNum::new();
        one.limbs[0] = 1;
        let mut two = one;
        two.limbs[0] = 2;
        [one, two]
    }

    // Hash to curve point generated with the message "P-384 Offset Generator"
    fn offset_generator() -> [Secp384r1Fq; 2] {
        [
            BigNum {
                limbs: [
                    0xbbd42576da117d6c47eea85c8e1861, 0x8cbe4f40c7719603e7e08f07010180, 0x5367a156f0b8626c8e74087b86a4dd, 0x16a096
                ]
            },
            BigNum {
                limbs: [
                    0x94c481405c72fd733b2b49c7090f89, 0x0b4286d5acee116de5c867a26c16a5, 0x854dab3f719d8a82154e80f12fbac6, 0x4c54a9
                ]
            }
        ]
    }

    // offset generator * 2^((NScalarSlices - 1) * 4) = offset generator * 2^380
    fn offset_generator_final() -> [Secp384r1Fq; 2] {
        [
            BigNum {
                limbs: [
                    0x1dcdb76c8967ffb7c38061fa0faaba, 0xe1b9a306cf7525514478ae95641ee9, 0xca3cf097d6157f69e0c598e4048365, 0xada8e5
                ]
            },
            BigNum {
                limbs: [
                    0xacabe5523d357bb362047c2ef6f9f4, 0xce8f8388547ea2168395de89be9b20, 0xc10fcc0229535d39cdc5f8f812f1ae, 0xd32067
                ]
            }
        ]
    }

    fn b() -> Secp384r1Fq {
        BigNum {
            limbs: [
                0x56398d8a2ed19d2a85c8edd3ec2aef, 0x9c6efe8141120314088f5013875ac6, 0xa7e23ee7e4988e056be3f82d19181d, 0xb3312f
            ]
        }
    }

    fn a() -> Secp384r1Fq {
        BigNum {
            limbs: [
                0xffffff0000000000000000fffffffc, 0xfffffffffffffffffffffffffffeff, 0xffffffffffffffffffffffffffffff, 0xffffff
            ]
        }
    }
}

fn from_u64<BN>(x: u64) -> BN where BN: BigNumTrait {
    BN::from([x as Field, 0, 0, 0])
}

fn to_u64<BN>(x: BN) -> u64 where BN: BigNumTrait {
    x.get_limb(0) as u64
}

fn to_le_bits<let TOTAL_BITS: u32, BN>(bn: BN) -> [u1; TOTAL_BITS] where BN: BigNumTrait {
    let mut bits: [u1; TOTAL_BITS] = [0; TOTAL_BITS];
    // Loop through limbs
    for l in 0..(TOTAL_BITS / 120) as u64 {
        let limb = bn.get_limb(l);
        let limb_bytes: [u8; 15] = limb.to_le_bytes();
        // Loop through limb bytes (120 bits per limb = 15 bytes)
        for j in 0..15 {
            let limb_byte = limb_bytes[j];
            // Loop through bits and extract each one
            for k in 0..8 {
                bits[(l * 120) as u64 + (j * 8 + k) as u64] = ((limb_byte >> k) & 1) as u1;
            }
        }
    }
    bits
}

type Secp384r1 = BigCurve<Secp384r1Fq, Secp384r1Params>;
type Secp384r1J = CurveJ<Secp384r1Fq, Secp384r1Params>;

unconstrained fn get_transcript(P: Secp384r1J, scalar: ScalarField<96>) -> [AffineTranscript<Secp384r1Fq>; 486] {
    let res = P.mul(scalar);
    let transcript = res.1;
    transcript.as_array()
}


global ZERO_FQ: Secp384r1Fq = BigNum::from_array([0; 4]);
global ZERO_FR: Secp384r1Fr = BigNum::from_array([0; 4]);

global ONE_FQ: Secp384r1Fq = BigNum::from_array([0x1, 0x0, 0x0, 0x0]);
global TWO_FQ: Secp384r1Fq = BigNum::from_array([0x2, 0x0, 0x0, 0x0]);
global THREE_FQ: Secp384r1Fq = BigNum::from_array([0x3, 0x0, 0x0, 0x0]);
global FOUR_FQ: Secp384r1Fq = BigNum::from_array([0x4, 0x0, 0x0, 0x0]);
global EIGHT_FQ: Secp384r1Fq = BigNum::from_array([0x8, 0x0, 0x0, 0x0]);

global SAMPLE_POINT_A: Secp384r1J = CurveJ {
    x: BigNum {
        limbs: [0xde274820369df628c9efee3af4bb5c, 0xc0d5e23b60cd872f161a32688ade84, 0x16822f016bf265f83fb8b63a98d332, 0xa79122]
    },
    y: BigNum {
        limbs: [0x7c970c818cb89c85318310b9ad5ca3, 0x153250caecab3f605799570782b6d4, 0xc80ab02ec91e85113860b2c178280f, 0xf081d0]
    },
    z: BigNum {
        limbs: [0x01, 0x00, 0x00, 0x00]
    },
    is_infinity: false
};
global SAMPLE_POINT_B: Secp384r1J = CurveJ {
    x: BigNum {
        limbs: [0x28f8164067647041aa9dcd808ac461, 0x1fbe6ff1a7f8b8a2a89fd4aa13944f, 0xfdf1da1497a5afc69957c9466caa0d, 0x4a67f0]
    },
    y: BigNum {
        limbs: [0xf0fa0708efcacd2b9f60ee5e3e85d5, 0xce4dab4a5b06184db358eaae29d7b6, 0x6f396164fd8f1ffcfac5c23a369392, 0x221d6e]
    },
    z: BigNum {
        limbs: [0x01, 0x00, 0x00, 0x00]
    },
    is_infinity: false
};

fn secp384r1_j_to_affine(p: Secp384r1J) -> Secp384r1 {
    let z_inv = p.z.__invmod();
    let z_inv_squared = z_inv.mul(z_inv);
    let z_inv_cubed = z_inv_squared.mul(z_inv);
    let x = p.x.mul(z_inv_squared);
    let y = p.y.mul(z_inv_cubed);
    BigCurve { x, y, is_infinity: p.is_infinity }
}

// Set as unconstrained for testing purposes
unconstrained fn verify_secp384r1_ecdsa(
    public_key_x: Secp384r1Fq,
    public_key_y: Secp384r1Fq,
    message_digest: [u8; 32],
    signature: (Secp384r1Fr, Secp384r1Fr)
) -> bool {
    // 1. Unpack the signature (r, s)
    let (r, s): (Secp384r1Fr, Secp384r1Fr) = signature;

    // 2. Compute e = HASH(m), where m is the message digest
    let e_bytes = std::hash::sha256(message_digest);
    let mut e_bytes_padded: [u8; 48] = [0; 48];
    for i in 0..32 {
        e_bytes_padded[i] = e_bytes[i];
    }
    let e: Secp384r1Fr = BigNum::from_be_bytes(e_bytes_padded);

    // 3. Compute w = s^-1 mod n
    let w = s.__invmod();
    // Check that s is in the inverse of w since the previous line is unconstrained
    assert(s.mul(w).eq(BigNum::one()));

    // 4. Compute u1 = ew mod n and u2 = rw mod n
    let u_1: ScalarField<96> = ScalarField::from_bignum(e.mul(w));
    let u_2: ScalarField<96> = ScalarField::from_bignum(r.mul(w));

    // Convert public key to jacobian coordinates
    let public_key: Secp384r1J = CurveJ { x: public_key_x, y: public_key_y, z: BigNum::one(), is_infinity: false };

    let gen: Secp384r1J = CurveJ {
        x: BigNum {
            limbs: [
                0x02f25dbf55296c3a545e3872760ab7, 0x3b628ba79b9859f741e082542a3855, 0x22be8b05378eb1c71ef320ad746e1d, 0xaa87ca
            ]
        },
        y: BigNum {
            limbs: [
                0x60b1ce1d7e819d7a431d7c90ea0e5f, 0x1dbd289a147ce9da3113b5f0b8c00a, 0x4a96262c6f5d9e98bf9292dc29f8f4, 0x3617de
            ]
        },
        z: BigNum::one(),
        is_infinity: false
    };

    // 5. Compute the point R = u1G + u2Q
    let (r_point, _) = CurveJ::msm([gen, public_key], [u_1, u_2]);

    println(f"r: {r}");
    println(f"r_point: {r_point}");
    let affine_r_point = secp384r1_j_to_affine(r_point);
    println(f"affine_r_point: {affine_r_point}");
    let r_point_x = r_point.x;
    //println(f"r_point.x: {r_point_x}");

    let r_point_x_as_fr: Secp384r1Fr = BigNum::from_array(affine_r_point.x.limbs);

    // 6. The signature is valid if r = R.x (mod n)
    // Need to have them in the same field to do the comparison
    r_point_x_as_fr.eq(r)
}

#[test]
fn test_ec_add() {
    let (c, _) = SAMPLE_POINT_A.add(SAMPLE_POINT_B);
    println(f"c: {c}");
    let affine_c = secp384r1_j_to_affine(c);
    println(f"affine_c: {affine_c}");
    affine_c.validate_on_curve();
    assert(c.eq(CurveJ {
        x: BigNum {
            limbs: [0xbe0ce3ebe570e0ccea732de87d5a6d, 0x353bf75dac182fa9d5eddc6abb14b8, 0x1177d4ae9d652e50a2fe6ec5ddb84b, 0xa87524]
        },
        y: BigNum {
            limbs: [0x19ce2d0b33c38f04f12e27b8408364, 0x4775a33829c426de4a449c4e29278e, 0xefe053bf776ff1e169a24dc5c909c7, 0x9e4802]
        },
        z: BigNum {
            limbs: [0x01, 0x00, 0x00, 0x00]
        },
        is_infinity: false
    }));
}

#[test]
fn test_ec_double() {
    let (double_a, _) = SAMPLE_POINT_A.dbl();
    println(f"double_a: {double_a}");
    let affine_double_a = secp384r1_j_to_affine(double_a);
    println(f"affine_double_a: {affine_double_a}");
    affine_double_a.validate_on_curve();
}

unconstrained fn test_ec_mul_impl() -> Secp384r1J {
    let one: Secp384r1Fr = BigNum::from_array([1, 0, 0, 0]);
    let scalar: ScalarField<96> = ScalarField::from_bignum(one);
    let (result, _) = SAMPLE_POINT_A.mul(scalar);
    result
}

#[test]
fn test_ec_mul() {
    let result = test_ec_mul_impl();
    println(f"result: {result}");
    assert(result.eq(CurveJ {
        x: BigNum {
            limbs: [0xde274820369df628c9efee3af4bb5c, 0xc0d5e23b60cd872f161a32688ade84, 0x16822f016bf265f83fb8b63a98d332, 0xa79122]
        },
        y: BigNum {
            limbs: [0x7c970c818cb89c85318310b9ad5ca3, 0x153250caecab3f605799570782b6d4, 0xc80ab02ec91e85113860b2c178280f, 0xf081d0]
        },
        z: BigNum {
            limbs: [0x01, 0x00, 0x00, 0x00]
        },
        is_infinity: false
    }));
}

#[test]
fn test_ec_msm() {
    let one: Secp384r1Fr = BigNum::from_array([1, 0, 0, 0]);
    let scalar: ScalarField<96> = ScalarField::from_bignum(one);
    let (result, _) = CurveJ::msm([SAMPLE_POINT_A, SAMPLE_POINT_B], [scalar, scalar]);
    let expected_result: Secp384r1J = CurveJ {
        x: BigNum {
            limbs: [0xbe0ce3ebe570e0ccea732de87d5a6d, 0x353bf75dac182fa9d5eddc6abb14b8, 0x1177d4ae9d652e50a2fe6ec5ddb84b, 0xa87524]
        },
        y: BigNum {
            limbs: [0x19ce2d0b33c38f04f12e27b8408364, 0x4775a33829c426de4a449c4e29278e, 0xefe053bf776ff1e169a24dc5c909c7, 0x9e4802]
        },
        z: BigNum {
            limbs: [0x01, 0x00, 0x00, 0x00]
        },
        is_infinity: false
    };
    println(f"result: {result}");
    assert(result.eq(expected_result));
}

// Runs into a stack overflow error
#[test]
fn test_secp384r1_signature_verification() {
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("Hello World! This is Noir-ECDSA".as_bytes());
    let r: Secp384r1Fr = BigNum {
        limbs: [
            0xc5bccdcdd6f753dd76c91bcb2fa0d9, 0xf6fd3cc7bf3a890ad61a1003b8ddbe, 0x1e8c60bdcf48ebce32441db3e1b930, 0xfbf1c1
        ]
    };
    let s: Secp384r1Fr = BigNum {
        limbs: [
            0x37163bfc6465d8decaf32f97686229, 0xbb8d1437125816198a83997d07bb04, 0xc0212d4076a052d75fd059eefae2ea, 0x8ad31c
        ]
    };
    let public_key_x: Secp384r1Fq = BigNum {
        limbs: [
            0x16a7f5d0a394c0f8151768021c3820, 0xbe57a2e57e6dfea24f0e2619fdeed6, 0xd3b7957c997cf7d74249b1e220cf82, 0x6aa5a1
        ]
    };
    let public_key_y: Secp384r1Fq = BigNum {
        limbs: [
            0x4b21697642909c890471b634a16c61, 0x5ef2367caf12d973ae4f0bc80cdfba, 0x8cf1475f01c1a1821aeee47c1fb504, 0x9b5ec7
        ]
    };
    assert(verify_secp384r1_ecdsa(public_key_x, public_key_y, sha256_hash, (r, s)));
}

