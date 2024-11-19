use ecdsa::secp384r1::verify_secp384r1_ecdsa;
use bigcurve::curves::secp384r1::{Secp384r1Fq, Secp384r1Fr};

fn main(
    public_key_x: Secp384r1Fq,
    public_key_y: Secp384r1Fq,
    message_digest: [u8; 32],
    signature_r: Secp384r1Fr,
    signature_s: Secp384r1Fr,
) {
    assert(verify_secp384r1_ecdsa(
        public_key_x,
        public_key_y,
        message_digest,
        (signature_r, signature_s),
    ));
}
