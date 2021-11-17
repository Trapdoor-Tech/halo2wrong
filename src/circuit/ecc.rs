use crate::rns::{Common, Integer, Rns};

use super::{integer::IntegerConfig, AssignedInteger};
use crate::circuit::integer::{IntegerChip, IntegerInstructions};
use crate::circuit::UnassignedInteger;
use crate::NUMBER_OF_LIMBS;
use halo2::arithmetic::{CurveAffine, FieldExt};
use halo2::circuit::Region;
use halo2::pasta::group::Curve;
use halo2::plonk::Error;
use num_bigint::BigUint as big_uint;

// TODO: are these traits all available?
#[derive(Default, Clone, Debug)]
pub struct Point<C: CurveAffine> {
    pub x: Integer<C::ScalarExt>,
    pub y: Integer<C::ScalarExt>,
}

/// E is emulated curve, C is the native curve
impl<C: CurveAffine> Point<C> {
    pub fn new_from_point<E: CurveAffine>(p: E, num_of_limbs: usize, bit_len: usize) -> Self {
        let (_x, _y) = p
            .coordinates()
            .map(|p| -> (big_uint, big_uint) {
                let x = num_bigint::BigUint::from_bytes_le(&p.x().to_bytes());
                let y = num_bigint::BigUint::from_bytes_le(&p.y().to_bytes());
                (x, y)
            })
            .unwrap();

        let x = Integer::<C::ScalarExt>::from_big(_x, num_of_limbs, bit_len);
        let y = Integer::<C::ScalarExt>::from_big(_y, num_of_limbs, bit_len);
        Self { x, y }
    }
}

impl<C: CurveAffine> Point<C> {
    pub fn new(x: Integer<C::ScalarExt>, y: Integer<C::ScalarExt>) -> Self {
        Point { x, y }
    }
}

#[derive(Debug, Clone)]
pub struct AssignedPoint<C: CurveAffine> {
    pub x: AssignedInteger<C::ScalarExt>,
    pub y: AssignedInteger<C::ScalarExt>,
}

/// Linear combination term
pub enum Term<C: CurveAffine> {
    Assigned(AssignedPoint<C>, AssignedInteger<C::ScalarExt>),
    Unassigned(Option<Point<C>>, AssignedInteger<C::ScalarExt>),
}

#[derive(Clone, Debug)]
pub struct EccConfig {
    // TODO: `pub` is unnecessary?
    pub integer_chip_config: IntegerConfig,
}

/// E is the emulated curve, C is the native curve
pub struct EccChip<E: CurveAffine, C: CurveAffine> {
    // config: EccConfig,
    // e_scalar_field: IntegerChip<E::ScalarExt, C::ScalarExt>
    // TODO: is `pub` necessary?
    pub config: EccConfig,
    pub e_base_field: IntegerChip<E::Base, C::ScalarExt>,
}

pub trait EccInstruction<E: CurveAffine, C: CurveAffine> {
    fn assign_point(&self, region: &mut Region<'_, C::ScalarExt>, point: Option<Point<C>>, offset: &mut usize) -> Result<AssignedPoint<C>, Error>;
    fn assert_is_on_curve(&self, region: &mut Region<'_, C::ScalarExt>, point: AssignedPoint<C>, offset: &mut usize) -> Result<(), Error>;
    fn assert_equal(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        p0: AssignedPoint<C>,
        p1: AssignedPoint<C>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C>, Error>;
    fn add(&self, region: &mut Region<'_, C::ScalarExt>, p0: AssignedPoint<C>, p1: AssignedPoint<C>, offset: &mut usize) -> Result<AssignedPoint<C>, Error>;
    fn double(&self, region: &mut Region<'_, C::ScalarExt>, p: AssignedPoint<C>, offset: &mut usize) -> Result<AssignedPoint<C>, Error>;
    fn mul_var(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        p: AssignedPoint<C>,
        e: AssignedInteger<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C>, Error>;
    fn mul_fix(&self, region: &mut Region<'_, C::ScalarExt>, p: E, e: AssignedInteger<C::ScalarExt>, offset: &mut usize) -> Result<AssignedPoint<C>, Error>;
    fn multi_exp(&self, region: &mut Region<'_, C::ScalarExt>, terms: Vec<Term<C>>, offset: &mut usize) -> Result<AssignedPoint<C>, Error>;
    fn combine(&self, region: &mut Region<'_, C::ScalarExt>, terms: Vec<Term<C>>, u: C::ScalarExt, offset: &mut usize) -> Result<AssignedPoint<C>, Error>;
}

impl<E: CurveAffine, C: CurveAffine> EccInstruction<E, C> for EccChip<E, C> {
    fn assign_point(&self, region: &mut Region<'_, C::ScalarExt>, point: Option<Point<C>>, offset: &mut usize) -> Result<AssignedPoint<C>, Error> {
        let x = self.e_base_field.range_assign_integer(
            region,
            UnassignedInteger::from(point.as_ref().map(|p| p.x.clone())),
            self.e_base_field.rns.bit_len_limb,
            offset,
        )?;
        let y = self.e_base_field.range_assign_integer(
            region,
            UnassignedInteger::from(point.as_ref().map(|p| p.y.clone())),
            self.e_base_field.rns.bit_len_limb,
            offset,
        )?;
        Ok(AssignedPoint { x, y })
    }

    fn assert_is_on_curve(&self, region: &mut Region<'_, C::ScalarExt>, point: AssignedPoint<C>, offset: &mut usize) -> Result<(), Error> {
        // TODO
        Ok(())
    }

    fn assert_equal(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        p0: AssignedPoint<C>,
        p1: AssignedPoint<C>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C>, Error> {
        Ok(p0)
    }

    fn add(&self, region: &mut Region<'_, C::ScalarExt>, p0: AssignedPoint<C>, p1: AssignedPoint<C>, offset: &mut usize) -> Result<AssignedPoint<C>, Error> {
        let to_base = |x: Integer<C::ScalarExt>| -> E::Base {
            let bytes_le = x.value().to_bytes_le();
            let mut u256 = [0u8; 32];
            u256[..bytes_le.len()].copy_from_slice(&bytes_le);
            E::Base::from_bytes(&u256).unwrap()
        };
        let to_scalar = |x: Integer<C::ScalarExt>| -> E::Scalar {
            let bytes_le = x.value().to_bytes_le();
            let mut u256 = [0u8; 32];
            u256[..bytes_le.len()].copy_from_slice(&bytes_le);
            E::Scalar::from_bytes(&u256).unwrap()
        };
        let p0_x = p0.x.integer().map(to_base);
        let p0_y = p0.y.integer().map(to_base);
        let p1_x = p1.x.integer().map(to_base);
        let p1_y = p1.y.integer().map(to_base);
        let sum = p0_x.map(|p0_x| {
            let p0 = E::from_xy(p0_x, p0_y.unwrap()).unwrap();
            let p1 = E::from_xy(p1_x.unwrap(), p1_y.unwrap()).unwrap();
            let sum = p0.add(p1).to_affine();
            Point::new_from_point(sum, NUMBER_OF_LIMBS, self.e_base_field.rns.bit_len_limb)
        });
        self.assign_point(region, sum, offset)
    }

    fn double(&self, region: &mut Region<'_, C::ScalarExt>, p: AssignedPoint<C>, offset: &mut usize) -> Result<AssignedPoint<C>, Error> {
        Ok(p)
    }

    fn mul_var(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        p: AssignedPoint<C>,
        e: AssignedInteger<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C>, Error> {
        let to_base = |x: Integer<C::ScalarExt>| -> E::Base {
            let bytes_le = x.value().to_bytes_le();
            let mut u256 = [0u8; 32];
            u256[..bytes_le.len()].copy_from_slice(&bytes_le);
            E::Base::from_bytes(&u256).unwrap()
        };
        let to_scalar = |x: Integer<C::ScalarExt>| -> E::Scalar {
            let bytes_le = x.value().to_bytes_le();
            let mut u256 = [0u8; 32];
            u256[..bytes_le.len()].copy_from_slice(&bytes_le);
            E::Scalar::from_bytes(&u256).unwrap()
        };
        let x = p.x.integer().map(to_base);
        let y = p.y.integer().map(to_base);
        let point = x.map(|x| {
            let p = E::from_xy(x, y.unwrap()).unwrap();
            let out = p.mul(e.integer().map(to_scalar).unwrap()).to_affine();
            Point::new_from_point(out, NUMBER_OF_LIMBS, self.e_base_field.rns.bit_len_limb)
        });
        self.assign_point(region, point, offset)
    }

    fn mul_fix(&self, region: &mut Region<'_, C::ScalarExt>, p: E, e: AssignedInteger<C::ScalarExt>, offset: &mut usize) -> Result<AssignedPoint<C>, Error> {
        let point = Point::new_from_point(p, NUMBER_OF_LIMBS, self.e_base_field.rns.bit_len_limb);
        let assigned_point = self.assign_point(region, Some(point), offset)?;
        self.mul_var(region, assigned_point, e, offset)
    }

    fn multi_exp(&self, region: &mut Region<'_, C::ScalarExt>, terms: Vec<Term<C>>, offset: &mut usize) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }

    fn combine(&self, region: &mut Region<'_, C::ScalarExt>, terms: Vec<Term<C>>, u: C::ScalarExt, offset: &mut usize) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }
}
