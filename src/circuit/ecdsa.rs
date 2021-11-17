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
pub struct EcdsaConfig {
    pub ecc_chip_config: EccConfig, // ecc
    pub scalar_config: IntegerConfig,
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

    // fn scalar_chip(&self) -> &IntegerChip<E::ScalarExt, C::ScalarExt> {
    //     &self.scalar_chip
    // }

    // TODO: shall we create a new scalar_chip and clone?
    fn scalar_chip(&self) -> IntegerChip<E::ScalarExt, C::ScalarExt> {
        let rns = self.scalar_chip.rns.clone();
        IntegerChip::<E::ScalarExt, C::ScalarExt>::new(self.config.scalar_config.clone(), rns.clone())
    }
}

// TODO: are these traits all available?
#[derive(Default, Clone, Debug)]
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

#[cfg(test)]
mod tests {
    use crate::NUMBER_OF_LIMBS;
    use crate::circuit::ecc::EccInstruction;
    use crate::circuit::ecdsa::{
        AssignedEcdsaSig, AssignedPoint, AssignedPublicKey, EccChip, EccConfig, EcdsaChip, EcdsaConfig, EcdsaSig, IntegerChip, IntegerInstructions, Point,
    };
    use crate::circuit::main_gate::MainGate;
    use crate::circuit::range::RangeChip;
    use crate::circuit::range::RangeInstructions;
    use crate::rns::{Integer, Rns, fe_to_big};
    use halo2::arithmetic::{CurveAffine, FieldExt, Field};
    use halo2::circuit::{Chip, Layouter, Region, SimpleFloorPlanner};
    use halo2::dev::MockProver;
    use halo2::plonk::{Circuit, ConstraintSystem, Error};
    use group::{Curve, prime::PrimeCurveAffine};

    #[derive(Clone, Debug)]
    struct TestCircuitEcdsaVerifyConfig {
        ecdsa_verify_config: EcdsaConfig,
    }

    impl TestCircuitEcdsaVerifyConfig {}

    // This test module is not finished yet
    #[derive(Default, Clone, Debug)]
    struct TestCircuitEcdsaVerify<E: CurveAffine, C: CurveAffine> {
        sig: EcdsaSig<C::ScalarExt>,
        pk: Point<C>,
        msg_hash: Option<Integer<C::ScalarExt>>,
        rns_base: Rns<E::Base, C::ScalarExt>,
        rns_scalar: Rns<E::ScalarExt, C::ScalarExt>,
    }

    // This test module is not finished yet
    impl<E: CurveAffine, C: CurveAffine> Circuit<C::ScalarExt> for TestCircuitEcdsaVerify<E, C> {
        type Config = TestCircuitEcdsaVerifyConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<C::ScalarExt>) -> Self::Config {
            // TODO: is this correct?
            let overflow_bit_lengths = vec![2, 3];

            let main_gate_config = MainGate::<C::ScalarExt>::configure(meta);
            let range_config = RangeChip::<C::ScalarExt>::configure(meta, &main_gate_config, overflow_bit_lengths.clone());
            let scalar_config = IntegerChip::<E::ScalarExt, C::ScalarExt>::configure(meta, &range_config, &main_gate_config);
            let ecc_scalar_config = IntegerChip::<E::Base, C::ScalarExt>::configure(meta, &range_config, &main_gate_config);
            let ecc_chip_config = EccConfig {
                integer_chip_config: ecc_scalar_config.clone(),
            };

            let ecdsa_verify_config = EcdsaChip::<E, C>::configure(meta, &ecc_chip_config, &scalar_config);
            TestCircuitEcdsaVerifyConfig { ecdsa_verify_config }
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<<C as CurveAffine>::ScalarExt>) -> Result<(), Error> {
            let ecc_base_chip =
                IntegerChip::<E::Base, C::ScalarExt>::new(config.ecdsa_verify_config.ecc_chip_config.integer_chip_config.clone(), self.rns_base.clone());
            let ecc_chip = EccChip::<E, C> {
                config: config.ecdsa_verify_config.ecc_chip_config.clone(),
                e_base_field: ecc_base_chip,
            };
            let scalar_chip = IntegerChip::<E::ScalarExt, C::ScalarExt>::new(config.ecdsa_verify_config.scalar_config.clone(), self.rns_scalar.clone());

            let ecdsa_chip = EcdsaChip::<E, C>::new(config.ecdsa_verify_config.clone(), ecc_chip, scalar_chip);

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;

                    // TODO: should not do this, instead we should use `assign_sig`
                    let r_assigned = ecdsa_chip.scalar_chip.assign_integer(&mut region, Some(self.sig.r.clone()), offset)?;
                    let s_assigned = ecdsa_chip.scalar_chip.assign_integer(&mut region, Some(self.sig.s.clone()), offset)?;
                    let sig = AssignedEcdsaSig {
                        r: r_assigned.clone(),
                        s: s_assigned.clone(),
                    };

                    // println!("assigned r = {:?}", r_assigned);

                    // TODO: should not do this, instead we should use `assign_point`
                    let x_assigned = ecdsa_chip.ecc_chip.e_base_field.assign_integer(&mut region, Some(self.pk.x.clone()), offset)?;
                    let y_assigned = ecdsa_chip.ecc_chip.e_base_field.assign_integer(&mut region, Some(self.pk.y.clone()), offset)?;
                    let pk = AssignedPublicKey {
                        point: AssignedPoint {
                            x: x_assigned.clone(),
                            y: y_assigned.clone(),
                        },
                    };

                    let msg_hash = ecdsa_chip.scalar_chip.assign_integer(&mut region, self.msg_hash.clone(), offset)?;

                    ecdsa_chip.verify(&mut region, &sig, &pk, &msg_hash, offset)
                },
            )?;

            // since we used `assert_in_field`, we need a range chip
            let range_chip = RangeChip::<C::ScalarExt>::new(config.ecdsa_verify_config.scalar_config.range_config.clone(), self.rns_scalar.bit_len_lookup);
            #[cfg(not(feature = "no_lookup"))]
            range_chip.load_limb_range_table(&mut layouter)?;
            #[cfg(not(feature = "no_lookup"))]
            range_chip.load_overflow_range_tables(&mut layouter)?;

            Ok(())
        }
    }

    // This test module is not finished yet
    #[test]
    fn test_pasta_ecdsa_verifier() {
        // assuming that we are verifying signature (in Fp curve) on Fq curve
        // which means signature's scalar field is Fq, base field is Fp
        // which in turn means E::ScalarExt == C::Base, E::Base == C::ScalarExt
        // p > q
        use halo2::pasta::EpAffine as C;
        use halo2::pasta::EqAffine as E;

        let bit_len_limb = 64;
        let rns_base = Rns::<<E as CurveAffine>::Base, <C as CurveAffine>::ScalarExt>::construct(bit_len_limb);
        let rns_scalar = Rns::<<E as CurveAffine>::ScalarExt, <C as CurveAffine>::ScalarExt>::construct(bit_len_limb);

        #[cfg(not(feature = "no_lookup"))]
        let k: u32 = (rns_base.bit_len_lookup + 1) as u32;
        #[cfg(feature = "no_lookup")]
        let k: u32 = 8;

        let generator = <E as PrimeCurveAffine>::generator();
        let sk = <E as CurveAffine>::ScalarExt::rand();
        let pk = generator * sk;
        let pk = pk.to_affine();

        let m_hash = <E as CurveAffine>::ScalarExt::rand();
        let randomness = <E as CurveAffine>::ScalarExt::rand();
        let randomness_inv = randomness.invert().unwrap();
        let sig_point = generator * randomness;
        let x = sig_point.to_affine().coordinates().unwrap().x().clone();
        let x_bytes = x.to_bytes();
        let x_bytes_on_n = <E as CurveAffine>::ScalarExt::from_bytes(&x_bytes).unwrap(); // get x cordinate (E::Base) on E::Scalar
        let integer_r = rns_scalar.new_from_big(fe_to_big(x_bytes_on_n));
        let integer_s = rns_scalar.new_from_big(fe_to_big(randomness_inv * (m_hash + x_bytes_on_n * sk)));

        let integer_m_hash = rns_scalar.new_from_big(fe_to_big(m_hash));

        let sig = EcdsaSig {
            r: integer_r.clone(),
            s: integer_s.clone(),
        };
        let pk = Point::new_from_point(pk, NUMBER_OF_LIMBS, bit_len_limb);
        let msg_hash = Some(integer_m_hash.clone());

        // testcase: normal
        let circuit = TestCircuitEcdsaVerify::<E, C> {
            sig,
            pk,
            msg_hash,
            rns_base,
            rns_scalar,
        };

        let prover = match MockProver::run(k, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        assert_eq!(prover.verify(), Ok(()));
    }
}
