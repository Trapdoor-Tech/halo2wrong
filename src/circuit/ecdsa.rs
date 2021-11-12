use crate::circuit::ecc::{AssignedPoint, EccChip, EccConfig, EccInstruction, Point};
use crate::circuit::integer::{IntegerChip, IntegerConfig};
use crate::circuit::AssignedInteger;
use crate::rns::Integer;
use halo2::arithmetic::{CurveAffine, FieldExt};
use halo2::circuit::{Chip, Region};
use halo2::plonk::{Circuit, Error};
// use secp256k1::Signature;

struct EcdsaConfig {
    ecc_chip_config: EccConfig, // ecc
    scalar_config: IntegerConfig,
}

struct EcdsaChip<C: CurveAffine, ScalarField: FieldExt> {
    config: EcdsaConfig,
    // chip to do secp256k1 ecc arithmetic
    ecc_chip: EccChip,
    // chip to do arithmetic over secp256k1's scalar field
    scalar_chip: IntegerChip<ScalarField, C::ScalarExt>,
}

impl<C: CurveAffine, ScalarField: FieldExt> Chip<C::ScalarExt> for EcdsaChip<C, ScalarField> {
    type Config = EcdsaConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        todo!()
    }

    fn loaded(&self) -> &Self::Loaded {
        todo!()
    }
}

pub struct EcdsaSig<F: FieldExt> {
    pub r: Integer<F>,
    pub s: Integer<F>,
}

// impl<C: CurveAffine> From<secp256k1::Signature> for EcdsaSig<C::ScalarExt> {
//     fn from(_: Signature) -> Self {
//         todo!()
//     }
// }

pub struct AssignedEcdsaSig<C: CurveAffine> {
    pub r: AssignedInteger<C::ScalarExt>,
    pub s: AssignedInteger<C::ScalarExt>,
}

pub struct AssignedPublicKey<C: CurveAffine> {
    pub point: AssignedPoint<C>,
}

impl<C: CurveAffine, ScalarField: FieldExt> EcdsaChip<C, ScalarField> {
    fn verify(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        sig: &AssignedEcdsaSig<C>,
        pk: &AssignedPublicKey<C>,
        msg_hash: &AssignedInteger<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<(), Error> {
        // 1. check 0 < r, s < n

        // 2. w = s^(-1) (mod n)

        // 3. u1 = m' * w (mod n)

        // 4. u2 = r * w (mod n)

        // 5. compute Q = u1*G + u2*pk
        // let _g = Point {
        //     x: Default::default(),
        //     y: Default::default(),
        // };
        // let g = self.ecc_chip.assign_point(region, _g, offset)?;

        // 6. check if Q.x == r (mod n)

        todo!()
    }
}
