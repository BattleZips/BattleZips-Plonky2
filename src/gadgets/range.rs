use crate::circuits::{D, F};
use anyhow::Result;
use plonky2::{field::types::Field, iop::target::Target, plonk::circuit_builder::CircuitBuilder};

/**
 * Given an existing target value, ensure that it is less than 10
 *
 * @param value - assigned value being queried for range
 * @param builder - circuit builder
 * @return - copy constraint fails if not < 10
 */
pub fn less_than_10(value: Target, builder: &mut CircuitBuilder<F, D>) -> Result<()> {
    let mut exp = builder.constant(F::ONE);
    for i in 0..9 {
        // copy value being compared
        let value_t = builder.add_virtual_target();
        builder.connect(value, value_t);
        // constant being checked for range equality
        let range_t = builder.constant(F::from_canonical_u8(i));
        // subtract value against constant to demonstrate range
        let checked_t = builder.sub(range_t, value_t);
        // multiply against range check expression
        exp = builder.mul(exp, checked_t);
    }
    // return boolean check on whether value is within range of 10
    let zero = builder.constant(F::ZERO);
    builder.connect(exp, zero);
    Ok(())
}
