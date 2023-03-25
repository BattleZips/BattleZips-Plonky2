use crate::utils::ship::Ship;

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
        let low = bits[0..64]
            .iter()
            .fold(0, |acc, &x| (acc << 1) | (x as u64));
        let high = bits[64..100]
            .iter()
            .fold(0, |acc, &x| (acc << 1) | (x as u64));
        // return canonical representation of a private board state
        [low, high]
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
