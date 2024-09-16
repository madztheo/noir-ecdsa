// Inspired by https://github.com/noir-lang/noir/blob/21425dedcc31287431a4a25589d52d5397e974bc/noir_stdlib/src/ec/swcurve.nr#L190
use dep::bignum::BigNum;
use dep::bignum::runtime_bignum::BigNumInstance;
use dep::bignum::runtime_bignum::BigNumTrait;
use dep::bignum::runtime_bignum::BigNumInstanceTrait;
use dep::bignum::runtime_bignum::BigNumParamsTrait;
use dep::bignum::fields::secp384r1Fq::Secp384r1_Fq_Params;
use dep::bignum::fields::secp384r1Fr::Secp384r1_Fr_Params;

type Secp384r1Fq = BigNum<4, Secp384r1_Fq_Params>;
type Secp384r1Fr = BigNum<4, Secp384r1_Fr_Params>;

fn from_u64<BN>(x: u64) -> BN where BN: BigNumTrait {
    BN::from([x as Field, 0, 0, 0]) 
}

fn to_u64<BN>(x: BN) -> u64 where BN: BigNumTrait {
    x.get_limb(0) as u64
}

fn to_le_bits(x: Secp384r1Fr) -> [u1; 384] {
    let mut bits = [0; 384];
    let mut tmp = x;
    // TODO: This is not correct, need to fix it
    // It does not consider the last bit
    for i in 0..383 {
        if !tmp.eq(ZERO_FR) {
            let (q, r) = tmp.udiv_mod(from_u64(2));
            bits[i] = to_u64(r) as u1;
            tmp = q;
        }
    }
    bits
}

// CurveGroup representation of Weierstraß curves
// Points are represented by three-dimensional Jacobian coordinates.
// See <https://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Jacobian_Coordinates> for details.

// Curve specification
struct Curve { // Short Weierstraß curve
    // Coefficients in defining equation y^2 = x^3 + axz^4 + bz^6
    a: Secp384r1Fq,
    b: Secp384r1Fq,
    // Generator as point in Cartesian coordinates
    gen: Point
}

// Point in three-dimensional Jacobian coordinates
struct Point {
    x: Secp384r1Fq,
    y: Secp384r1Fq,
    z: Secp384r1Fq // z = 0 corresponds to point at infinity.
}

// c.f. https://neuromancer.sk/std/secg/secp384r1
global SECP384R1_CURVE: Curve = Curve::new(
    BigNum::from_array([0xffffff0000000000000000fffffffc, 0xfffffffffffffffffffffffffffeff, 0xffffffffffffffffffffffffffffff, 0xffffff]),
    BigNum::from_array([0x56398d8a2ed19d2a85c8edd3ec2aef, 0x9c6efe8141120314088f5013875ac6, 0xa7e23ee7e4988e056be3f82d19181d, 0xb3312f]),
    Point::new(
        BigNum::from_array([0x02f25dbf55296c3a545e3872760ab7, 0x3b628ba79b9859f741e082542a3855, 0x22be8b05378eb1c71ef320ad746e1d, 0xaa87ca]),
        BigNum::from_array([0x60b1ce1d7e819d7a431d7c90ea0e5f, 0x1dbd289a147ce9da3113b5f0b8c00a, 0x4a96262c6f5d9e98bf9292dc29f8f4, 0x3617de]),
        BigNum::from_array([0x1, 0x0, 0x0, 0x0])
    )
);

global ZERO_FQ: Secp384r1Fq = BigNum::from_array([0; 4]);
global ZERO_FR: Secp384r1Fr = BigNum::from_array([0; 4]);

global ONE_FQ: Secp384r1Fq = BigNum::from_array([0x1, 0x0, 0x0, 0x0]);
global TWO_FQ: Secp384r1Fq = BigNum::from_array([0x2, 0x0, 0x0, 0x0]);
global THREE_FQ: Secp384r1Fq = BigNum::from_array([0x3, 0x0, 0x0, 0x0]);
global FOUR_FQ: Secp384r1Fq = BigNum::from_array([0x4, 0x0, 0x0, 0x0]);
global EIGHT_FQ: Secp384r1Fq = BigNum::from_array([0x8, 0x0, 0x0, 0x0]);

global SAMPLE_POINT_A: Point = Point::new(
    BigNum::from_array([0xde274820369df628c9efee3af4bb5c, 0xc0d5e23b60cd872f161a32688ade84, 0x16822f016bf265f83fb8b63a98d332, 0xa79122]),
    BigNum::from_array([0x7c970c818cb89c85318310b9ad5ca3, 0x153250caecab3f605799570782b6d4, 0xc80ab02ec91e85113860b2c178280f, 0xf081d0]),
    BigNum::from_array([0x01, 0x00, 0x00, 0x00])
);
global SAMPLE_POINT_B: Point = Point::new(
    BigNum::from_array([0x28f8164067647041aa9dcd808ac461, 0x1fbe6ff1a7f8b8a2a89fd4aa13944f, 0xfdf1da1497a5afc69957c9466caa0d, 0x4a67f0]),
    BigNum::from_array([0xf0fa0708efcacd2b9f60ee5e3e85d5, 0xce4dab4a5b06184db358eaae29d7b6, 0x6f396164fd8f1ffcfac5c23a369392, 0x221d6e]),
    BigNum::from_array([0x01, 0x00, 0x00, 0x00])
);  

impl Point {
    // Point constructor
    pub fn new(x: Secp384r1Fq, y: Secp384r1Fq, z: Secp384r1Fq) -> Self {
        Self { x, y, z }
    }

    // Check if zero
    pub fn is_zero(self) -> bool {
        self.eq(Point::zero())
    }

    // Additive identity
    pub fn zero() -> Self {
        Self { 
            x: ZERO_FQ, 
            y: ZERO_FQ, 
            z: ZERO_FQ 
        }
    }

    // Negation
    fn negate(self) -> Self {
        let Self {x, y, z} = self;
        Self { 
            x, 
            y: y.neg(), 
            z 
        }
    }
}

impl Eq for Point {
    fn eq(self, p: Point) -> bool {
        let Point {x: x1, y: y1, z: z1} = self;
        let Point {x: x2, y: y2, z: z2} = p;

        ((z1.eq(ZERO_FQ)) & (z2.eq(ZERO_FQ))) | ((!z1.eq(ZERO_FQ)) & (!z2.eq(ZERO_FQ)) & (x1.mul(z2).mul(z2).eq(x2.mul(z1).mul(z1))) & (y1.mul(z2).mul(z2).mul(z2).eq(y2.mul(z1).mul(z1).mul(z1))))
    }
}

impl Curve {
    // Curve constructor
    pub fn new(a: Secp384r1Fq, b: Secp384r1Fq, gen: Point) -> Curve {
        // Check curve coefficients
        assert(!from_u64::<Secp384r1Fq>(4).mul(a).mul(a).mul(a).add(from_u64::<Secp384r1Fq>(27).mul(b).mul(b)).eq(ZERO_FQ));

        let curve = Curve { a, b, gen };

        // gen should be on the curve
        assert(curve.contains(curve.gen));

        curve
    }

    // Membership check
    pub fn contains(self, p: Point) -> bool {
        let Point {x, y, z} = p;

        let xx = x.mul(x);
        let zz = z.mul(z);
        let zzzz = zz.mul(zz);

        let lhs = y.mul(y);
        let mut rhs = xx.mul(x).add(self.a.mul(x).mul(zzzz));
        rhs = rhs.add(self.b.mul(zzzz.mul(zz)));

        lhs.eq(rhs)
    }

    // Addition
    pub fn add(self, p1: Point, p2: Point) -> Point {
        if p1.is_zero() {
            p2
        } else if p2.is_zero() {
            p1
        } else {
            let Point {x: x1, y: y1, z: z1} = p1;
            let Point {x: x2, y: y2, z: z2} = p2;

            let z1z1 = z1.mul(z1);
            let z2z2 = z2.mul(z2);

            let you1 = x1.mul(z2z2);
            let you2 = x2.mul(z1z1);

            let s1 = y1.mul(z2z2.mul(z2));
            let s2 = y2.mul(z1z1.mul(z1));

            if you1.eq(you2) {
                if !s1.eq(s2) {
                    Point::zero()
                } else {
                    self.double(p1)
                }
            } else {
                let h = you2.sub(you1);
                let r = s2.sub(s1);

                let hh = h.mul(h);
                let hhh = hh.mul(h);

                let mut x3 = r.mul(r).sub(hhh);
                x3 = x3.sub(you1.mul(hh).mul(TWO_FQ));

                let mut y3 = r.mul(you1.mul(hh).sub(x3));
                y3 = y3.sub(s1.mul(hhh));
                let z3 = h.mul(z1).mul(z2);

                Point { x: x3, y: y3, z: z3 }
            }
        }
    }

    // Point doubling
    pub fn double(self, p: Point) -> Point {
        let Point {x, y, z} = p;

        if p.is_zero() {
            p
        } else if y.eq(ZERO_FQ) {
            Point::zero()
        } else {
            let xx = x.mul(x);
            let yy = y.mul(y);
            let yyyy = yy.mul(yy);

            let zzzz = z.mul(z).mul(z);

            let s = FOUR_FQ.mul(x.mul(yy));
            let m = THREE_FQ.mul(xx).add(self.a.mul(zzzz));

            let x0 = m.mul(m).sub(s.mul(TWO_FQ));
            let y0 = m.mul(s.sub(x0)).sub(EIGHT_FQ.mul(yyyy));
            let z0 = y.mul(z).mul(TWO_FQ);

            Point{ x: x0, y: y0, z: z0 }
        }
    }

    // Scalar multiplication with scalar represented by a bit array (little-endian convention).
    // If k is the natural number represented by `bits`, then this computes p + ... + p k times.
    fn bit_mul<let N: u32>(self, bits: [u1; N], p: Point) -> Point {
        let mut out = Point::zero();

        for i in 0..N {
            out = self.add(
                self.add(out, out),
                if(bits[N - i - 1] == 0) {Point::zero()} else {p});
        }

        out
    }

    // Scalar multiplication (p + ... + p n times)
    pub fn mul(self, n: Secp384r1Fr, p: Point) -> Point {
        let mut n_as_bits: [u1; 384] = to_le_bits(n);
        self.bit_mul(n_as_bits, p)
    }

    // Multi-scalar multiplication (n[0]*p[0] + ... + n[N]*p[N], where * denotes scalar multiplication)
    fn msm<let N: u32>(self, n: [Secp384r1Fr; N], p: [Point; N]) -> Point {
        let mut out = Point::zero();

        for i in 0..N {
            out = self.add(out, self.mul(n[i], p[i]));
        }

        out
    }

    // Point subtraction
    pub fn subtract(self, p1: Point, p2: Point) -> Point {
        self.add(p1, p2.negate())
    }

    // Simplified SWU map-to-curve method
    /*fn swu_map(self, z: BigNum, u: BigNum) -> Point {
        self.into_affine().swu_map(z, u).into_group()
    }*/
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
    let u_1 = e.mul(w);
    let u_2 = r.mul(w);

    println(f"u_1: {u_1}");
    println(f"u_2: {u_2}");

    // Convert public key to jacobian coordinates
    let public_key = Point::new(public_key_x, public_key_y, BigNum::one());

    let u_1G = SECP384R1_CURVE.mul(u_1, SECP384R1_CURVE.gen);
    let u_2Q = SECP384R1_CURVE.mul(u_2, public_key);

    println(f"u_1G: {u_1G}");
    println(f"u_2Q: {u_2Q}");

    // 5. Compute the point R = u1G + u2Q
    let r_point: Point = SECP384R1_CURVE.add(u_1G, u_2Q);

    println(f"r: {r}");
    let r_point_x = r_point.x;
    println(f"r_point.x: {r_point_x}");

    // 6. The signature is valid if r ≡ R.x (mod n)
    // Need to have them in the same field to do the comparison
    //r.eq(r_point_x)

    false
}

#[test]
fn test_ec_contains() {
    assert(SECP384R1_CURVE.contains(SAMPLE_POINT_A));
    assert(SECP384R1_CURVE.contains(SAMPLE_POINT_B));
}

#[test]
fn test_ec_add() {
    let c = SECP384R1_CURVE.add(SAMPLE_POINT_A, SAMPLE_POINT_B);   
    println(f"c: {c}");
    assert(SECP384R1_CURVE.contains(c));
}

#[test]
fn test_ec_double() {
    let double_a = SECP384R1_CURVE.double(SAMPLE_POINT_A);
    assert(SECP384R1_CURVE.contains(double_a));
    println(f"double_a: {double_a}");
} 

// Unable to run this test as it takes too long to run
#[test]
fn test_ec_mul() {
    let a = SECP384R1_CURVE.mul(from_u64::<Secp384r1Fr>(1), SAMPLE_POINT_A);
    assert(SECP384R1_CURVE.contains(a));
    println(f"a: {a}");
}

// Runs into a stack overflow error
#[test]
fn test_secp384r1_signature_verification() {
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("Hello World! This is Noir-ECDSA".as_bytes());
    let r: Secp384r1Fr = BigNum::from_array([0xc5bccdcdd6f753dd76c91bcb2fa0d9, 0xf6fd3cc7bf3a890ad61a1003b8ddbe, 0x1e8c60bdcf48ebce32441db3e1b930, 0xfbf1c1]);
    let s: Secp384r1Fr = BigNum::from_array([0x37163bfc6465d8decaf32f97686229, 0xbb8d1437125816198a83997d07bb04, 0xc0212d4076a052d75fd059eefae2ea, 0x8ad31c]);
    let public_key_x: Secp384r1Fq = BigNum::from_array([0x16a7f5d0a394c0f8151768021c3820, 0xbe57a2e57e6dfea24f0e2619fdeed6, 0xd3b7957c997cf7d74249b1e220cf82, 0x6aa5a1]);
    let public_key_y: Secp384r1Fq = BigNum::from_array([0x4b21697642909c890471b634a16c61, 0x5ef2367caf12d973ae4f0bc80cdfba, 0x8cf1475f01c1a1821aeee47c1fb504, 0x9b5ec7]);
    assert(verify_secp384r1_ecdsa(public_key_x, public_key_y, sha256_hash, (r, s)));
}
