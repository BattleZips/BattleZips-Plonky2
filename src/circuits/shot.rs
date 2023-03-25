use super::{C, D, F};
use crate::{
    gadgets::{
        board::hash_board,
        shot::{check_hit, serialize_shot},
    },
    utils::board::Board,
};
use anyhow::Result;
use plonky2::{
    field::types::{Field, PrimeField64},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        proof::ProofWithPublicInputs,
    },
};

pub struct ShotCircuitOutputs {
    shot: u64,
    hit: u64,
    commitment: [u64; 4],
}

pub struct ShotCircuit {
    data: CircuitData<F, C, D>,
    board_t: [Target; 2],
    shot_t: [Target; 2],
}

impl ShotCircuit {
    /**
     * Build the circuit for proving a hit/ miss of a shot on a committed board
     *
     * @return - object storing circuit data and input targets
     */
    pub fn new() -> Result<ShotCircuit> {
        // CONFIG //
        let mut config = CircuitConfig::standard_recursion_config();
        // set wires for random access gate
        config.num_wires = 137;
        config.num_routed_wires = 130;
        // config.zero_knowledge = true;

        // SYNTHESIS//
        // define circuit builder
        let mut builder = CircuitBuilder::<F, D>::new(config);
        // input targets
        let board_t: [Target; 2] = builder.add_virtual_targets(2).try_into().unwrap();
        let shot_t: [Target; 2] = builder.add_virtual_targets(2).try_into().unwrap();
        // serialize shot coordinate
        let serialized_t = serialize_shot(shot_t[0], shot_t[1], &mut builder).unwrap();
        // export serialized shot value
        builder.register_public_input(serialized_t);
        // check for hit or miss
        let hit = check_hit(board_t, serialized_t, &mut builder).unwrap();
        // export hit/ miss boolean
        builder.register_public_input(hit);
        // compute public hash of board
        let board_hash_t = hash_board(board_t, &mut builder).unwrap();
        // export binding commitment to board publicly
        // @dev todo: making commitment blinding as well
        builder.register_public_inputs(&board_hash_t.elements);
        // return circuit data
        let data = builder.build::<C>();
        Ok(Self {
            data,
            board_t,
            shot_t,
        })
    }

    /**
     * Compute the proof of a shot on a board
     *
     * @param self - instance of ShotCircuit to constrain computation
     * @param board - ship positions on board
     * @param shot - coordinate being queried for hit/ miss (limited to 10x10 board)
     * @return - proof of execution, along with public outputs:
     *   - public_outputs[0] = hit/ miss boolean
     *   - public_outputs[1..5] = public commitment to private board state checked
     */
    pub fn prove(&self, board: Board, shot: [u64; 2]) -> Result<ProofWithPublicInputs<F, C, D>> {
        // marshall board into canonical form
        let board_canonical = board.canonical();

        // witness inputs
        let mut pw = PartialWitness::new();
        pw.set_target(self.board_t[0], F::from_canonical_u64(board_canonical[0]));
        pw.set_target(self.board_t[1], F::from_canonical_u64(board_canonical[1]));
        pw.set_target(self.shot_t[0], F::from_canonical_u64(shot[0]));
        pw.set_target(self.shot_t[1], F::from_canonical_u64(shot[1]));

        // constrained computation of shot hit/miss with proof
        self.data.prove(pw)
    }

    /**
     * Verify the integrity of a given shot proof
     *
     * @param proof: previously computed shot proof being verified
     * @return - status of verifier check
     */
    pub fn verify(&self, proof: ProofWithPublicInputs<F, C, D>) -> Result<()> {
        self.data.verify(proof.clone())
    }

    /**
     * Decode the output of a shot proof
     *
     * @param proof - proof from shot circuit
     * @return - formatted outputs from shot ciruit
     */
    pub fn decode_public(proof: ProofWithPublicInputs<F, C, D>) -> Result<ShotCircuitOutputs> {
        let public_inputs = proof.clone().public_inputs;
        let shot = public_inputs[0].to_canonical_u64();
        let hit = public_inputs[1].to_canonical_u64();
        let commitment: [u64; 4] = public_inputs[2..6]
            .iter()
            .map(|x| x.to_canonical_u64())
            .collect::<Vec<u64>>()
            .try_into()
            .unwrap();
        Ok(ShotCircuitOutputs {
            shot,
            hit,
            commitment,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::utils::{board::Board, ship::Ship};

    // Carrier: 3, 4, false
    // Battleship: 9, 6, true
    // Cruiser: 0, 0, false
    // Submarine: 0, 6, false
    // Destroyer: 6, 1, true
    // (Y)
    // 9 | 0 0 0 0 0 0 0 0 0 1
    // 8 | 0 0 0 0 0 0 0 0 0 1
    // 7 | 0 0 0 0 0 0 0 0 0 1
    // 6 | 1 1 1 0 0 0 0 0 0 1
    // 5 | 0 0 0 0 0 0 0 0 0 0
    // 4 | 0 0 0 1 1 1 1 1 0 0
    // 3 | 0 0 0 0 0 0 0 0 0 0
    // 2 | 0 0 0 0 0 0 1 0 0 0
    // 1 | 0 0 0 0 0 0 1 0 0 0
    // 0 | 1 1 1 0 0 0 0 0 0 0
    //    -------------------- (X)
    //     0 1 2 3 4 5 6 7 8 9

    #[test]
    fn test_shot_hit() {
        // define inputs
        let board = Board::new(
            Ship::new(3, 4, false),
            Ship::new(9, 6, true),
            Ship::new(0, 0, false),
            Ship::new(0, 6, false),
            Ship::new(6, 1, true),
        );
        let shot = [0, 0];

        // build circuit
        let circuit = ShotCircuit::new().unwrap();

        // compute proof
        let proof = circuit.prove(board.clone(), shot).unwrap();

        // verify integrity of
        assert_eq!((), circuit.verify(proof.clone()).unwrap());

        // verify integrity of public exports
        let output = ShotCircuit::decode_public(proof.clone()).unwrap();
        let expected_shot = 0u64;
        let expected_hit = 1u64;
        let expected_commitment = board.hash();
        assert_eq!(output.shot, expected_shot);
        assert_eq!(output.hit, expected_hit);
        assert_eq!(output.commitment, expected_commitment);
    }

    #[test]
    fn test_shot_miss() {
        // define inputs
        let board = Board::new(
            Ship::new(3, 4, false),
            Ship::new(9, 6, true),
            Ship::new(0, 0, false),
            Ship::new(0, 6, false),
            Ship::new(6, 1, true),
        );
        let shot = [0, 1];

        // build circuit
        let circuit = ShotCircuit::new().unwrap();

        // compute proof
        let proof = circuit.prove(board.clone(), shot).unwrap();

        // verify integrity of
        assert_eq!((), circuit.verify(proof.clone()).unwrap());

        // verify integrity of public exports
        let output = ShotCircuit::decode_public(proof.clone()).unwrap();
        let expected_shot = 10u64;
        let expected_hit = 0u64;
        let expected_commitment = board.hash();
        assert_eq!(output.shot, expected_shot);
        assert_eq!(output.hit, expected_hit);
        assert_eq!(output.commitment, expected_commitment);
    }
}
