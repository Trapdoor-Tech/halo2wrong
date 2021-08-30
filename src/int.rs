use halo2::arithmetic::FieldExt;
use halo2::circuit::Cell;
use num_bigint::BigUint as big_uint;
use num_integer::Integer as _;
use num_traits::{Num, One, Zero};
use std::convert::TryInto;
use std::marker::PhantomData;
use std::ops::Shl;

pub(crate) const CRT_MODULUS_BIT_LEN: usize = 256;
pub(crate) const NUMBER_OF_LIMBS: usize = 4;
pub(crate) const BIT_LEN_LIMB: usize = 64;

pub(crate) const NUMBER_OF_LOOKUP_LIMBS: usize = 4;
pub(crate) const BIT_LEN_LOOKUP_LIMB: usize = 16;

pub trait Common {
    fn value(&self) -> big_uint;

    fn eq(&self, other: &Self) -> bool {
        self.value() == other.value()
    }
}

fn fe_to_big<F: FieldExt>(fe: F) -> big_uint {
    big_uint::from_bytes_le(&fe.to_bytes()[..])
}

fn field_modulus<F: FieldExt>() -> big_uint {
    big_uint::from_str_radix(&F::MODULUS[2..], 16).unwrap()
}

fn big_to_fe<F: FieldExt>(e: big_uint) -> F {
    F::from_str(&e.to_str_radix(10)[..]).unwrap()
}

#[derive(Debug, Clone)]
pub struct Rns<Wrong: FieldExt, Native: FieldExt> {
    pub bit_len: usize,
    pub number_of_limbs: usize,
    crt_modulus_bit_len: usize,
    right_shifter: Native,
    wrong_modulus: big_uint,
    negative_wrong_modulus: Decomposed<Native>,
    s: Native,
    two_limb_mask: big_uint,
    _marker_wrong: PhantomData<Wrong>,
}

impl<Wrong: FieldExt, Native: FieldExt> Rns<Wrong, Native> {
    pub(crate) fn new(bit_len: usize, number_of_limbs: usize, crt_modulus_bit_len: usize) -> Self {
        let two_inv = Native::from_u64(2).invert().unwrap();
        let right_shifter = two_inv.pow(&[2 * bit_len as u64, 0, 0, 0]);
        let wrong_modulus = big_uint::from_str_radix(&Wrong::MODULUS[2..], 16).unwrap();

        let t = big_uint::one() << crt_modulus_bit_len;
        let negative_wrong_modulus =
            Decomposed::<Native>::from_big(t - wrong_modulus.clone(), number_of_limbs, bit_len);
        let s = big_to_fe(big_uint::one() << bit_len);
        let two_limb_mask = (big_uint::one() << (bit_len * 2)) - 1usize;

        Rns {
            bit_len,
            number_of_limbs,
            crt_modulus_bit_len,
            right_shifter,
            wrong_modulus,
            negative_wrong_modulus,
            s,
            two_limb_mask,
            _marker_wrong: PhantomData,
        }
    }

    pub(crate) fn new_integer(&self, fe: Wrong) -> Integer<Wrong, Native> {
        self.new_integer_from_big(fe_to_big(fe))
    }

    pub(crate) fn rand_integer(&self) -> Integer<Wrong, Native> {
        self.new_integer(Wrong::rand())
    }

    pub(crate) fn wrong_modulus(&self) -> Integer<Wrong, Native> {
        self.new_integer_from_big(field_modulus::<Wrong>())
    }

    pub(crate) fn new_integer_from_big(&self, e: big_uint) -> Integer<Wrong, Native> {
        let modulus = big_uint::from_str_radix(&Wrong::MODULUS[2..], 16).unwrap();
        Integer {
            decomposed: Decomposed::from_big(e, self.number_of_limbs, self.bit_len),
            rns: &self,
        }
    }

    pub(crate) fn new_decomposed(&self, limb: &Limb<Native>) -> Decomposed<Native> {
        Decomposed::<Native>::from_big(limb.value(), self.number_of_limbs, self.bit_len)
    }
}

impl<'a, W: FieldExt, N: FieldExt> From<Integer<'a, W, N>> for big_uint {
    fn from(el: Integer<W, N>) -> Self {
        el.value()
    }
}

impl<F: FieldExt> From<Decomposed<F>> for big_uint {
    fn from(decomposed: Decomposed<F>) -> Self {
        decomposed.value()
    }
}

impl<F: FieldExt> From<Limb<F>> for big_uint {
    fn from(limb: Limb<F>) -> Self {
        limb.value()
    }
}

pub struct Reduced<'a, W: FieldExt, N: FieldExt> {
    pub r: Integer<'a, W, N>,
    pub q: Limb<N>,
    pub t: Vec<Limb<N>>,
    pub u0: N,
    pub u1: N,
}

#[derive(Debug, Clone)]
pub struct Integer<'a, Wrong: FieldExt, Native: FieldExt> {
    pub decomposed: Decomposed<Native>,
    pub rns: &'a Rns<Wrong, Native>,
}

impl<'a, W: FieldExt, N: FieldExt> Common for Integer<'a, W, N> {
    fn value(&self) -> big_uint {
        self.decomposed.value()
    }
}

impl<'a, W: FieldExt, N: FieldExt> Integer<'a, W, N> {
    pub(crate) fn fe(&self) -> W {
        big_to_fe(self.value())
    }

    fn limbs(&self) -> Vec<Limb<N>> {
        self.decomposed.limbs.clone()
    }

    pub(crate) fn add(&self, other: &Self) -> Self {
        let rns = self.rns;

        let limbs: Vec<Limb<N>> = self
            .decomposed
            .limbs
            .iter()
            .zip(other.decomposed.limbs.iter())
            .map(|(self_limb, other_limb)| (self_limb.value() + other_limb.value()).into())
            .collect();

        let decomposed = Decomposed {
            limbs,
            bit_len: rns.bit_len,
        };

        assert_eq!(decomposed.value(), self.value() + other.value());

        Integer { decomposed, rns }
    }

    pub(crate) fn reduce(&self) -> Reduced<'a, W, N> {
        let rns = self.rns;
        let modulus = rns.wrong_modulus.clone();
        let negative_modulus = rns.negative_wrong_modulus.clone();

        // compute quotient and the resultF
        let (q, r) = self.value().div_rem(&modulus);
        assert!(q < big_uint::one() << rns.bit_len);
        let q: Limb<N> = q.into();

        // q must stay in single limb

        // compute temp values
        let t: Vec<Limb<N>> = self
            .limbs()
            .iter()
            .zip(negative_modulus.limbs.iter())
            .map(|(a, p)| {
                let t = a.fe() + p.fe() * q.fe();
                Limb::from_fe(t)
            })
            .collect();

        let r = rns.new_integer_from_big(r);

        let (u0, u1) = self.residues(t.clone(), r.clone());

        Reduced { r, q, t, u0, u1 }
    }

    fn residues(&self, t: Vec<Limb<N>>, r: Integer<W, N>) -> (N, N) {
        // for now works only for this case
        let rns = self.rns;
        assert_eq!(rns.number_of_limbs, 4);
        let s = rns.s;

        let u0 =
            t[0].fe() + s * t[1].fe() - r.decomposed.limbs[0].fe() - s * r.decomposed.limbs[1].fe();

        let u1 =
            t[2].fe() + s * t[3].fe() - r.decomposed.limbs[2].fe() - s * r.decomposed.limbs[3].fe();

        let u1 = u1 + u0 * self.rns.right_shifter;

        // sanity check
        {
            let mask = rns.two_limb_mask.clone();
            let u0: big_uint = fe_to_big(u0);
            let u1: big_uint = fe_to_big(u1);
            assert_eq!(u0 & mask.clone(), big_uint::zero());
            assert_eq!(u1 & mask, big_uint::zero());
        }

        let u0 = u0 * self.rns.right_shifter;
        let u1 = u1 * self.rns.right_shifter;

        (u0, u1)
    }
}

#[derive(Debug, Clone)]
pub struct Limb<F: FieldExt> {
    pub cell: Option<Cell>,
    _value: F,
}

impl<F: FieldExt> Common for Limb<F> {
    fn value(&self) -> big_uint {
        fe_to_big(self._value)
    }
}

impl<F: FieldExt> Default for Limb<F> {
    fn default() -> Self {
        Limb {
            _value: F::zero(),
            cell: None,
        }
    }
}

impl<F: FieldExt> From<big_uint> for Limb<F> {
    fn from(e: big_uint) -> Self {
        Self {
            _value: big_to_fe(e),
            cell: None,
        }
    }
}

impl<F: FieldExt> From<Decomposed<F>> for Limb<F> {
    fn from(decomposed: Decomposed<F>) -> Self {
        let e: big_uint = decomposed.into();
        Limb::from(e)
    }
}

impl<F: FieldExt> Limb<F> {
    pub fn from_fe(fe: F) -> Limb<F> {
        big_uint::from_bytes_le(&fe.to_bytes()[..]).into()
    }

    pub fn fe(&self) -> F {
        self._value
    }
}

#[derive(Debug, Clone, Default)]
pub struct Decomposed<F: FieldExt> {
    pub limbs: Vec<Limb<F>>,
    bit_len: usize,
}

impl<F: FieldExt> Common for Decomposed<F> {
    fn value(&self) -> big_uint {
        let mut e = big_uint::zero();
        for (i, limb) in self.limbs.iter().enumerate() {
            e += limb.value() << (self.bit_len * i)
        }
        e
    }
}

impl<F: FieldExt> Decomposed<F> {
    pub fn from_limb(limb: &Limb<F>, number_of_limbs: usize, bit_len: usize) -> Self {
        Decomposed::from_big(limb.value(), number_of_limbs, bit_len)
    }

    pub fn from_big(e: big_uint, number_of_limbs: usize, bit_len: usize) -> Self {
        let mut e = e;
        let mask = big_uint::from(1usize).shl(bit_len) - 1usize;
        let limbs: Vec<Limb<F>> = (0..number_of_limbs)
            .map(|_| {
                let limb = mask.clone() & e.clone();
                e = e.clone() >> bit_len;
                limb.into()
            })
            .collect();

        Decomposed {
            limbs: limbs.try_into().expect("must fit in"),
            bit_len,
        }
    }
}

#[cfg(test)]
mod tests {

    use super::{field_modulus, Decomposed, Rns};

    use super::{Common, Limb};
    use num_bigint::BigUint as big_uint;
    use num_traits::Zero;
    use pasta_curves::{arithmetic::FieldExt, Fp, Fq};

    #[test]
    fn test_big_int() {
        const NUMBER_OF_LIMBS_LEVEL_1: usize = 4;
        const BIT_LEN_LIMB_LEVEL_1: usize = 64;
        const CRT_LEVEL_1: usize = 256;

        const NUMBER_OF_LIMBS_LEVEL_2: usize = 4;
        const BIT_LEN_LIMB_LEVEL_2: usize = 16;

        let rns = Rns::<Fp, Fq>::new(BIT_LEN_LIMB_LEVEL_1, NUMBER_OF_LIMBS_LEVEL_1, CRT_LEVEL_1);

        let a0_fe = Fp::rand();
        let a0 = rns.new_integer(a0_fe);
        assert_eq!(a0.fe(), a0_fe);

        // let a1_fe = Fp::rand();
        // let a1 = rns.new_integer::<_, Fq>(a1_fe);

        // // let (q, r) = a0.mul(&a1);
        // // assert_eq!(
        // //     big_uint::zero(),
        // //     a0.value() * a1.value() - q.value() * field_modulus::<Fp>() - r.value()
        // // );

        // let rns_lookup = Rns::new(BIT_LEN_LIMB_LEVEL_2, NUMBER_OF_LIMBS_LEVEL_2, CRT_LEVEL_2);

        for limb in a0.decomposed.limbs.iter() {
            let decomposed_limb =
                Decomposed::<Fq>::from_limb(limb, NUMBER_OF_LIMBS_LEVEL_2, BIT_LEN_LIMB_LEVEL_2);
            assert!(limb.eq(&Limb::from(decomposed_limb)));
        }
    }
}