use crate::circuit::ecc::{AssignedPoint, EccChip, EccConfig, EccInstruction, Point};
use crate::circuit::integer::{IntegerChip, IntegerConfig, IntegerInstructions};
use crate::circuit::AssignedInteger;
use crate::rns::Integer;
use crate::NUMBER_OF_LIMBS;
use halo2::arithmetic::{CurveAffine, FieldExt};
use halo2::circuit::{Chip, Region};
use halo2::plonk::{Circuit, ConstraintSystem, Error};
use num_bigint::BigUint as big_uint;
// use secp256k1::Signature;

use crate::rns::Rns;

#[derive(Clone, Debug)]
struct EcdsaConfig {
    ecc_chip_config: EccConfig, // ecc
    scalar_config: IntegerConfig,
}

/// E is the emulated curve, C is the native curve
struct EcdsaChip<E: CurveAffine, C: CurveAffine> {
    config: EcdsaConfig,
    // chip to do secp256k1 ecc arithmetic
    ecc_chip: EccChip<E, C>,
    // chip to do arithmetic over secp256k1's scalar field
    scalar_chip: IntegerChip<E::ScalarExt, C::ScalarExt>,
}

// impl<C: CurveAffine, ScalarField: FieldExt> Chip<C::ScalarExt> for EcdsaChip<C, ScalarField> {
//     type Config = EcdsaConfig;
//     type Loaded = ();

//     fn config(&self) -> &Self::Config {
//         &self.config
//     }

//     fn loaded(&self) -> &Self::Loaded {
//         &()
//     }
// }

impl<E: CurveAffine, C: CurveAffine> EcdsaChip<E, C> {
    pub fn new(config: EcdsaConfig, ecc_chip: EccChip<E, C>, scalar_chip: IntegerChip<E::ScalarExt, C::ScalarExt>) -> Self {
        EcdsaChip { config, ecc_chip, scalar_chip }
    }

    pub fn configure(_: &mut ConstraintSystem<C::ScalarExt>, ecc_chip_config: &EccConfig, scalar_config: &IntegerConfig) -> EcdsaConfig {
        EcdsaConfig {
            ecc_chip_config: ecc_chip_config.clone(),
            scalar_config: scalar_config.clone(),
        }
    }

    fn scalar_chip(&self) -> &IntegerChip<E::ScalarExt, C::ScalarExt> {
        &self.scalar_chip
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

impl<E: CurveAffine, C: CurveAffine> EcdsaChip<E, C> {
    fn verify(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        sig: &AssignedEcdsaSig<C>,
        pk: &AssignedPublicKey<C>,
        msg_hash: &AssignedInteger<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<(), Error> {
        let scalar_chip = self.scalar_chip();

        // 1. check 0 < r, s < n

        // // since `assert_not_zero` already includes a in-field check, we can just call `assert_not_zero`
        // scalar_chip.assert_in_field(region, &sig.r, offset)?;
        // scalar_chip.assert_in_field(region, &sig.s, offset)?;
        scalar_chip.assert_not_zero(region, &sig.r, offset)?;
        scalar_chip.assert_not_zero(region, &sig.s, offset)?;

        // 2. w = s^(-1) (mod n)
        let (s_inv, _) = scalar_chip.invert(region, &sig.s, offset)?;

        // 3. u1 = m' * w (mod n)
        let u1 = scalar_chip.mul(region, &msg_hash, &s_inv, offset)?;

        // 4. u2 = r * w (mod n)
        let u2 = scalar_chip.mul(region, &sig.r, &s_inv, offset)?;

        // 5. compute Q = u1*G + u2*pk
        let g1 = self.ecc_chip.mul_fix(region, E::generator(), u1, offset)?;
        let g2 = self.ecc_chip.mul_var(region, pk.point.clone(), u2, offset)?;
        let Q = self.ecc_chip.add(region, g1, g2, offset)?;

        // 6. check if Q.x == r (mod n)
        let Q_x = Q.x.clone();
        scalar_chip.assert_equal(region, &Q_x, &sig.r, offset)?;

        Ok(())
    }
}

// mod tests {
//     use crate::circuit::ecdsa::AssignedEcdsaSig;
//     use crate::circuit::ecdsa::AssignedPoint;
//     use crate::circuit::ecdsa::EccConfig;
//     use crate::circuit::ecdsa::EcdsaChip;
//     use crate::circuit::ecdsa::EcdsaConfig;
//     use crate::circuit::ecdsa::EcdsaSig;
//     use crate::circuit::ecdsa::Point;
//     use crate::circuit::integer::IntegerChip;
//     use crate::circuit::main_gate::MainGate;
//     use crate::circuit::range::RangeChip;
//     use crate::rns::Integer;
//     use crate::rns::Rns;
//     use halo2::arithmetic::{CurveAffine, FieldExt};
//     use halo2::circuit::SimpleFloorPlanner;
//     use halo2::circuit::{Chip, Layouter, Region};
//     use halo2::plonk::ConstraintSystem;
//     use halo2::plonk::{Circuit, Error};

//     #[derive(Clone, Debug)]
//     struct TestCircuitEcdsaVerifyConfig {
//         ecdsa_config: EcdsaConfig,
//     }

//     impl TestCircuitEcdsaVerifyConfig {}

//     #[derive(Default, Clone, Debug)]
//     struct TestCircuitEcdsaVerify<C: CurveAffine, N: FieldExt> {
//         sig: EcdsaSig<N>,
//         pk: Point<C>,
//         msg_hash: Option<Integer<N>>,
//         rns: Rns<C::ScalarExt, N>,
//     }

//     impl<C: CurveAffine, N: FieldExt> Circuit<N> for TestCircuitEcdsaVerify<C, N> {
//         type Config = TestCircuitEcdsaVerifyConfig;
//         type FloorPlanner = SimpleFloorPlanner;

//         fn without_witnesses(&self) -> Self {
//             Self::default()
//         }

//         fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
//             let main_gate_config = MainGate::<N>::configure(meta);

//             // TODO: what's this used for?
//             let overflow_bit_lengths = vec![2, 3];

//             let range_config = RangeChip::<N>::configure(meta, &main_gate_config, overflow_bit_lengths);
//             let scalar_config = IntegerChip::configure(meta, &range_config, &main_gate_config);

//             let ecc_chip_config = EccConfig {
//                 integer_chip_config: scalar_config.clone(),
//             };

//             let ecdsa_verify_config = EcdsaChip::<C, N>::configure(meta, &ecc_chip_config, &scalar_config);
//             TestCircuitEcdsaVerifyConfig { ecdsa_verify_config }
//         }

//         fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
//             let ecdsa_chip = EcdsaChip::<C, N>::new(config.clone());

//             layouter.assign_region(
//                 || "region 0",
//                 |mut region| {
//                     let offset = &mut 0;

//                     // TODO: should not do this, instead we should use `assign_sig`
//                     let r_assigned = ecdsa_chip.scalar_chip.assign_integer(&mut region, self.sig.r.clone(), offset)?;
//                     let s_assigned = ecdsa_chip.scalar_chip.assign_integer(&mut region, self.sig.s.clone(), offset)?;
//                     let sig = AssignedEcdsaSig {
//                         r: r_assigned.clone(),
//                         s: s_assigned.clone(),
//                     };

//                     // TODO: should not do this, instead we should use `assign_point`
//                     let x_assigned = ecdsa_chip.scalar_chip.assign_integer(&mut region, self.pk.x.clone(), offset)?;
//                     let y_assigned = ecdsa_chip.scalar_chip.assign_integer(&mut region, self.pk.y.clone(), offset)?;
//                     let pk = AssignedPoint {
//                         x: x_assigned.clone(),
//                         y: y_assigned.clone(),
//                     };

//                     let msg_hash = ecdsa_chip.scalar_chip.assign_integer(&mut region, self.msg_hash.clone(), offset)?;

//                     ecdsa_chip.verify(&mut region, &sig, &pk, &msg_hash, offset)
//                 },
//             )?;

//             Ok(())
//         }
//     }

//     #[cfg(test)]
//     fn test_ecdsa_verifier() {
//         use halo2::pasta::Fp as Wrong;
//         use halo2::pasta::Fq as Native;

//         let bit_len_limb = 64;
//         let rns = Rns::<Wrong, Native>::construct(bit_len_limb);

//         #[cfg(not(feature = "no_lookup"))]
//         let k: u32 = (rns.bit_len_lookup + 1) as u32;
//         #[cfg(feature = "no_lookup")]
//         let k: u32 = 8;

//         let integer_a = rns.rand_prenormalized();
//         let integer_b = rns.rand_prenormalized();

//         let integer_x = rns.rand_prenormalized();
//         let integer_y = rns.rand_prenormalized();

//         let integer_m_hash = rns.rand_prenormalized();

//         let sig = EcdsaSig {
//             r: integer_r.clone(),
//             s: integer_s.clone(),
//         };
//         let pk = Point { x: integer_x, y: integer_y };
//         let msg_hash = Some(integer_m_hash.clone());

//         // testcase: normal
//         let circuit = TestCircuitEcdsaVerifyConfig::<Wrong, Native> {
//             sig,
//             pk,
//             msg_hash,
//             rns: rns.clone(),
//         };

//         let prover = match MockProver::run(k, &circuit, vec![]) {
//             Ok(prover) => prover,
//             Err(e) => panic!("{:#?}", e),
//         };

//         assert_eq!(prover.verify(), Ok(()));
//     }
// }
