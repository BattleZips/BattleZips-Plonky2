use crate::circuits::F;
use crate::utils::ship::Ship;
use plonky2::{
    field::types::{Field, PrimeField64},
    hash::poseidon::PoseidonHash,
    plonk::config::Hasher,
};

#[derive(Debug, Clone)]
pub struct Board {
    pub carrier: Ship<5>,
    pub battleship: Ship<4>,
    pub cruiser: Ship<3>,
    pub submarine: Ship<3>,
    pub destroyer: Ship<2>,
}

impl Board {
    pub fn new(
        carrier: Ship<5>,
        battleship: Ship<4>,
        cruiser: Ship<3>,
        submarine: Ship<3>,
        destroyer: Ship<2>,
    ) -> Self {
        Self {
            carrier,
            battleship,
            cruiser,
            submarine,
            destroyer,
        }
    }

    /**
     * Add a ship to the board
     *
     * @param ship - ship to add to the board
     * @param board - board to add the ship to as a mutable reference
     */
    fn add_ship<const L: usize>(ship: &Ship<L>, board: &mut [bool; 100]) {
        for coordinate in ship.coordinates() {
            board[coordinate as usize] = true;
        }
    }

    /**
     * Turn the board into a LE-serialized representation of the ship placements as 100 bits
     *
     * @return - 100 bools representing the full board state
     */
    pub fn bits(&self) -> [bool; 100] {
        // empty board state
        let mut board = [false; 100];
        // flip bits for ship coordinates
        Board::add_ship(&self.carrier, &mut board);
        Board::add_ship(&self.battleship, &mut board);
        Board::add_ship(&self.cruiser, &mut board);
        Board::add_ship(&self.submarine, &mut board);
        Board::add_ship(&self.destroyer, &mut board);
        // return board with all ships applied
        board
    }

    /**
     * Turn the board into a LE-serialized representation of the ship placements as u64-serialized u128
     * @dev last 28 bits unused
     *
     * @return - 2 u64s representing the full board state
     */
    pub fn canonical(&self) -> [u64; 2] {
        // get board as 100 LE bits
        let bits = self.bits();
        // convert into 2 u64s
        let mut result = [0u64; 2];
        for (index, &bit) in bits.iter().enumerate() {
            if bit {
                let array_index = index / 64;
                let bit_index = index % 64;
                result[array_index] |= 1u64 << bit_index;
            }
        }

        result
    }

    /**
     * Hash the board state into a 4 u64 array
     * @todo
     */
    pub fn hash(&self) -> [u64; 4] {
        // get board state as canonical serialized u128
        let board: [F; 2] = self
            .canonical()
            .iter()
            .map(|x| F::from_canonical_u64(*x))
            .collect::<Vec<F>>()
            .try_into()
            .unwrap();
        // hash board state into 4 u64s
        PoseidonHash::hash_no_pad(&board)
            .elements
            .iter()
            .map(|x| x.to_canonical_u64())
            .collect::<Vec<u64>>()
            .try_into()
            .unwrap()
    }

    /**
     * Render ASCII to the console representing the ship placement
     */
    pub fn print(&self) {
        let mut lines = Vec::<String>::new();
        let board = self.bits();
        for i in 0..100 {
            if i % 10 == 0 {
                let mut out = format!("{} |", i / 10);
                for j in 0..10 {
                    out = format!("{} {}", out, board[i + j] as u8);
                }
                lines.push(out);
            }
        }
        lines.push(String::from(" (Y)"));
        lines.reverse();
        lines.push(String::from("   -------------------- (X)"));
        lines.push(String::from("    0 1 2 3 4 5 6 7 8 9"));
        for line in lines {
            println!("{}", line);
        }
    }

    pub fn print_canonical(board: &[u64; 2]) {
        // convert board into 100 LE bits
        let mut bits = [false; 100];
        for i in 0..100 {
            bits[i] = (board[i / 64] >> (i % 64)) & 1 == 1;
        }
        // render board
        let mut lines = Vec::<String>::new();
        for i in 0..100 {
            if i % 10 == 0 {
                let mut out = format!("{} |", i / 10);
                for j in 0..10 {
                    out = format!("{} {}", out, bits[i + j] as u8);
                }
                lines.push(out);
            }
        }
        lines.push(String::from(" (Y)"));
        lines.reverse();
        lines.push(String::from("   -------------------- (X)"));
        lines.push(String::from("    0 1 2 3 4 5 6 7 8 9"));
        for line in lines {
            println!("{}", line);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_board_print() {
        let board = Board::new(
            Ship::new(3, 4, false),
            Ship::new(9, 6, true),
            Ship::new(0, 0, false),
            Ship::new(0, 6, false),
            Ship::new(6, 1, true),
        );

        board.print();
    }
}
