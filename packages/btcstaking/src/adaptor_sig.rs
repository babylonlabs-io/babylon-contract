use bitcoin::secp256k1::Parity;
use bitcoin::XOnlyPublicKey;
use k256::elliptic_curve::group::prime::PrimeCurveAffine;
use k256::{
    elliptic_curve::{
        ops::{MulByGenerator, Reduce},
        point::{AffineCoordinates, DecompressPoint},
        PrimeField,
    },
    AffinePoint, ProjectivePoint, Scalar, U256,
};
use sha2::Digest;

/// MODNSCALAR_SIZE is the size of a scalar on the secp256k1 curve
const MODNSCALAR_SIZE: usize = 32;

/// JACOBIAN_POINT_SIZE is the size of a point on the secp256k1 curve in
/// compressed form
const JACOBIAN_POINT_SIZE: usize = 33;

/// ADAPTOR_SIGNATURE_SIZE is the size of a Schnorr adaptor signature
/// It is in the form of (R, s, needsNegation) where `R` is a point,
/// `s` is a scalar, and `needsNegation` is a boolean value
const ADAPTOR_SIGNATURE_SIZE: usize = JACOBIAN_POINT_SIZE + MODNSCALAR_SIZE + 1;

#[allow(non_snake_case)]
pub struct AdaptorSignature {
    R: ProjectivePoint,
    s_hat: Scalar,
    needs_negation: bool,
}

#[allow(non_snake_case)]
fn bytes_to_point(bytes: &[u8]) -> Result<ProjectivePoint, String> {
    let is_y_odd = bytes[0] == 0x03;
    let R_option = AffinePoint::decompress(
        k256::FieldBytes::from_slice(&bytes[1..]),
        k256::elliptic_curve::subtle::Choice::from(is_y_odd as u8),
    );
    let R = if R_option.is_some().into() {
        R_option.unwrap()
    } else {
        return Err("Failed to decompress R point".to_string());
    };
    // Convert AffinePoint to ProjectivePoint
    Ok(ProjectivePoint::from(R))
}

#[allow(non_snake_case)]
impl AdaptorSignature {
    pub fn verify(
        &self,
        pub_key: &XOnlyPublicKey,
        enc_key: &XOnlyPublicKey,
        msg: [u8; 32],
    ) -> Result<(), String> {
        // Convert public keys to points
        let pk = pub_key.public_key(Parity::Even);
        let P = bytes_to_point(&pk.serialize())?;
        let ek = enc_key.public_key(Parity::Even);
        let T = bytes_to_point(&ek.serialize())?;

        // Calculate R' = R - T (or R + T if negation is needed)
        let R_hat = if self.needs_negation {
            self.R + T
        } else {
            self.R - T
        };
        // Convert R' to affine coordinates
        let R_hat = R_hat.to_affine();

        // Calculate e = tagged_hash("BIP0340/challenge", bytes(R) || bytes(P) || m)
        // mod n
        let R_bytes = self.R.to_affine().x();
        let p_bytes = pub_key.serialize();
        let e = <Scalar as Reduce<U256>>::reduce_bytes(
            &eots::tagged_hash(eots::CHALLENGE_TAG)
                .chain_update(R_bytes)
                .chain_update(p_bytes)
                .chain_update(msg)
                .finalize(),
        );

        // Calculate expected R' = s'*G - e*P
        let s_hat_g = ProjectivePoint::mul_by_generator(&self.s_hat);
        let e_p = P * e;
        let expected_R_hat = s_hat_g - e_p;

        // Convert expected R' to affine coordinates
        let expected_R_hat = expected_R_hat.to_affine();

        // Ensure expected R' is not the point at infinity
        if expected_R_hat.is_identity().into() {
            return Err("Expected R' is the point at infinity".to_string());
        }

        // Ensure expected R'.y is even
        if expected_R_hat.y_is_odd().into() {
            return Err("Expected R'.y is odd".to_string());
        }

        // Ensure R' == expected R'
        if !R_hat.eq(&expected_R_hat) {
            return Err("R' does not match expected R'".to_string());
        }

        Ok(())
    }

    #[allow(non_snake_case)]
    pub fn new(asig_bytes: &[u8]) -> Result<Self, String> {
        if asig_bytes.len() != ADAPTOR_SIGNATURE_SIZE {
            return Err(format!(
                "malformed bytes for an adaptor signature: expected: {}, actual: {}",
                ADAPTOR_SIGNATURE_SIZE,
                asig_bytes.len()
            ));
        }
        // get R
        if asig_bytes[0] != 0x02 && asig_bytes[0] != 0x03 {
            return Err("Invalid first byte of adaptor signature".to_string());
        }
        let is_y_odd = asig_bytes[0] == 0x03;
        let R_option = AffinePoint::decompress(
            k256::FieldBytes::from_slice(&asig_bytes[1..JACOBIAN_POINT_SIZE]),
            k256::elliptic_curve::subtle::Choice::from(is_y_odd as u8),
        );
        let R = if R_option.is_some().into() {
            R_option.unwrap().into()
        } else {
            return Err("Failed to decompress R point".to_string());
        };

        // get s_hat
        let s_hat_bytes = &asig_bytes[JACOBIAN_POINT_SIZE..JACOBIAN_POINT_SIZE + MODNSCALAR_SIZE];
        let s_hat_field_bytes = *k256::FieldBytes::from_slice(s_hat_bytes);
        let s_hat = Scalar::from_repr_vartime(s_hat_field_bytes)
            .ok_or("failed to get s_hat in an adaptor signature")?;

        let needs_negation = asig_bytes[JACOBIAN_POINT_SIZE + MODNSCALAR_SIZE] == 0x01;
        Ok(AdaptorSignature {
            R,
            s_hat,
            needs_negation,
        })
    }
}
