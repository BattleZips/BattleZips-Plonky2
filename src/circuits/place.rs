use anyhow::Result;
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, VerifierCircuitData, VerifierCircuitTarget},
        config::{GenericConfig, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    },
};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

// L: length of ship placement
pub struct ShipPlacementTargets<const L: usize> {
    board_pre: [Target; 2],
    board_post: [Target; 2],
    ship: [Target; 3], // x, y, z
}

// pub fn compute_ship_placement_target_indexes<const L: usize>(ship: [Target; 3]) -> Result<()> {
//     let config = CircuitConfig::standard_recursion_config();
//     let pw = PartialWitness::new();
//     let mut builder = CircuitBuilder::<F, D>::new(config);
//     let limbs = {
//         let front = builder.split_le(board_pre[0], 64);
//         let back = builder.split_le(board_pre[1], 64);
//         front
//     };
//     println!("limbs = {:?}", limbs);
//     Ok(())
// }

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

/**
 * Given a ship head coordinate, orientation, and offset, compute the occupied coordinate + a boolean of whether offset coordinate is in range
 * @dev copy constraint will fail if x/ y coordinate is not in range
 *
 * @param x - x coordinate of ship head
 * @param y - y coordinate of ship head
 * @param z - orientation of ship head
 * @param offset - offset from ship head
 * @param builder - circuit builder
 * @return - coordinate of ship placement
 */
pub fn generate_coordiante(
    x: Target,
    y: Target,
    z: BoolTarget,
    offset: usize,
    builder: &mut CircuitBuilder<F, D>,
) -> Result<(Target)> {
    // define constants: offset length & y serialization (mul by 10)
    let offset_t = builder.constant(F::from_canonical_u8(offset as u8));
    let ten_t = builder.constant(F::from_canonical_u8(10));
    // add offsets to x
    let x_offset_t = builder.add(x, offset_t);
    let y_offset_t = builder.add(y, offset_t);
    // check range for offset coordinate plane cooresponding to orinentiation
    let range_check_t = builder.select(z, y_offset_t, x_offset_t);
    less_than_10(range_check_t, builder)?;
    // multiplex values for final coordiante expression
    let x_t = builder.select(z, x, x_offset_t);
    let y_t = builder.select(z, y_offset_t, y);
    // compute coordinate value
    let y_serialized_t = builder.mul(y_t, ten_t);
    Ok(builder.add(x_t, y_serialized_t))
}

/**
 * Given a ship as (x, y, z) with a constant ship length, compute the occupied coordinates
 *
 * @param ship - ship instantiation coordinates
 * @param builder - circuit builder
 */
pub fn ship_to_coordinates<const L: usize>(
    ship: (Target, Target, BoolTarget),
    builder: &mut CircuitBuilder<F, D>,
) -> Result<[Target; L]> {
    // connect values
    let (x, y, z) = ship;
    let x_t = builder.add_virtual_target();
    builder.connect(x, x_t);
    let y_t = builder.add_virtual_target();
    builder.connect(y, y_t);

    // range check ship head
    less_than_10(x_t, builder)?;
    less_than_10(y_t, builder)?;
    // build ship placement coordinate array
    let coordinates = builder.add_virtual_target_arr::<L>();
    for i in 0..L {
        let coordinate = generate_coordiante(x_t, y_t, z, i, builder)?;
        // println!("coordinate = {:?}", coordinate.);
        builder.connect(coordinate, coordinates[i]);
    }
    builder.register_public_inputs(&coordinates);
    Ok(coordinates)
}

pub fn decompose_board(
    board: [Target; 2],
    builder: &mut CircuitBuilder<F, D>,
) -> Result<[BoolTarget; 100]> {
    // define virtual
    let bits = {
        let front = builder.split_le(board[0], 64);
        let back = builder.split_le(board[1], 36);
        front.iter().chain(back.iter()).copied().collect::<Vec<_>>()
    };

    Ok(bits.try_into().unwrap())
}

// use ensure to check constraints
// pub fn place_ship() -> Result<()> {
//     let config = CircuitConfig::standard_recursion_config();
//     let mut builder = CircuitBuilder::<F, D>::new(config);

//     let board_pre: [Target; 2] = builder.add_virtual_targets(2).try_into().unwrap();
//     Ok(())
// }

#[cfg(test)]
mod tests {
    use plonky2::field::types::PrimeField64;

    use super::*;

    // #[test]
    // fn test_compute_ship_placement_target_indexes() {
    //     let ship = [Target::new(0), Target::new(1), Target::new(2)];
    //     let targets = compute_ship_placement_target_indexes::<3>(ship);
    //     println!("targets = {:?}", targets);
    // }

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[test]
    fn test_decompose_board() {
        // config
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // targets
        let board_pre: [Target; 2] = builder.add_virtual_targets(2).try_into().unwrap();

        // decompose into bits
        let bits = decompose_board(board_pre, &mut builder).unwrap();
        println!("bits: {:?}", bits);
        // proof inputs
        let board = [10u64, 20];
        let mut pw = PartialWitness::new();
        pw.set_target(board_pre[0], F::from_canonical_u64(board[0]));
        pw.set_target(board_pre[1], F::from_canonical_u64(board[0]));

        // prove board placement
        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        // verify board placement
        let res = data.verify(proof);
        println!("yay: {:?}", res);
    }

    #[test]

    fn test_ship_to_coordinates() {
        // config
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // targets
        let ship: (Target, Target, BoolTarget) = {
            let x = builder.add_virtual_target();
            let y = builder.add_virtual_target();
            let z = builder.add_virtual_bool_target_safe();
            (x, y, z)
        };
        const L: usize = 5; // ship size of 5
        let coordinates: [Target; L] = ship_to_coordinates::<L>(ship, &mut builder).unwrap();

        // proof inputs
        let mut pw = PartialWitness::new();
        pw.set_target(ship.0, F::from_canonical_u64(3));
        pw.set_target(ship.1, F::from_canonical_u64(3));
        pw.set_bool_target(ship.2, true);

        // prove board placement
        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        println!("coordinates: {:?}", coordinates);

        // verify board placement
        let res = data.verify(proof.clone());
        for i in 0..L {
            let coordinate = proof.public_inputs[i].to_canonical();
            println!("coordinate {}: {:?}", i, coordinate);
        }
    }
}
