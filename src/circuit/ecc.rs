use crate::rns::{Integer, Rns};

use super::{integer::IntegerConfig, AssignedInteger};
use crate::circuit::integer::IntegerChip;
use halo2::arithmetic::{CurveAffine, FieldExt};
use halo2::circuit::Region;
use halo2::plonk::Error;
use num_bigint::BigUint as big_uint;

pub struct Point<C: CurveAffine> {
    x: Integer<C::ScalarExt>,
    y: Integer<C::ScalarExt>,
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
    integer_chip_config: IntegerConfig,
}

/// E is the emulated curve, C is the native curve
pub struct EccChip<E: CurveAffine, C: CurveAffine> {
    config: EccConfig,
    pub e_base_field: IntegerChip<E::Base, C::ScalarExt>,
    // e_scalar_field: IntegerChip<E::ScalarExt, C::ScalarExt>
}

pub trait EccInstruction<E: CurveAffine, C: CurveAffine> {
    fn assign_point(&self, region: &mut Region<'_, C::ScalarExt>, point: Point<C>, offset: &mut usize) -> Result<AssignedPoint<C>, Error>;
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
    fn assign_point(&self, region: &mut Region<'_, C::ScalarExt>, point: Point<C>, offset: &mut usize) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }

    fn assert_is_on_curve(&self, region: &mut Region<'_, C::ScalarExt>, point: AssignedPoint<C>, offset: &mut usize) -> Result<(), Error> {
        unimplemented!();
    }

    fn assert_equal(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        p0: AssignedPoint<C>,
        p1: AssignedPoint<C>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }

    fn add(&self, region: &mut Region<'_, C::ScalarExt>, p0: AssignedPoint<C>, p1: AssignedPoint<C>, offset: &mut usize) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }

    fn double(&self, region: &mut Region<'_, C::ScalarExt>, p: AssignedPoint<C>, offset: &mut usize) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }

    fn mul_var(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        p: AssignedPoint<C>,
        e: AssignedInteger<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }

    fn mul_fix(&self, region: &mut Region<'_, C::ScalarExt>, p: E, e: AssignedInteger<C::ScalarExt>, offset: &mut usize) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }

    fn multi_exp(&self, region: &mut Region<'_, C::ScalarExt>, terms: Vec<Term<C>>, offset: &mut usize) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }

    fn combine(&self, region: &mut Region<'_, C::ScalarExt>, terms: Vec<Term<C>>, u: C::ScalarExt, offset: &mut usize) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }
}
