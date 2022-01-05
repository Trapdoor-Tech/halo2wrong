use super::IntegerChip;
use crate::circuit::main_gate::MainGateInstructions;
use crate::circuit::{AssignedInteger, AssignedLimb};
use crate::rns::Common;
use crate::NUMBER_OF_LIMBS;
use halo2::arithmetic::{FieldExt, BaseExt};
use halo2::circuit::Region;
use halo2::plonk::Error;

impl<W: BaseExt, N: FieldExt> IntegerChip<W, N> {
    pub(super) fn _sub(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        b: &AssignedInteger<N>,
        offset: &mut usize,
    ) -> Result<AssignedInteger<N>, Error> {
        let main_gate = self.main_gate();

        let aux = self.rns.make_aux(b.max_vals());
        let aux_limbs = aux.limbs();
        let aux_native = aux.native();
        let mut c_limbs: Vec<AssignedLimb<N>> = Vec::with_capacity(NUMBER_OF_LIMBS);

        for idx in 0..NUMBER_OF_LIMBS {
            let a_limb = a.limb(idx);
            let b_limb = b.limb(idx);

            let aux = aux_limbs[idx];
            let c_max = a_limb.add_fe(aux);
            let c_limb = main_gate.sub_with_constant(region, a_limb, b_limb, aux, offset)?;

            c_limbs.push(AssignedLimb::<N>::new(c_limb.cell, c_limb.value, c_max))
        }

        let c_native = main_gate.sub_with_constant(region, a.native(), b.native(), aux_native, offset)?;

        Ok(self.new_assigned_integer(c_limbs, c_native))
    }
}
