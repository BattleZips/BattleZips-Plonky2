#[derive(Debug, Clone)]
pub struct Ship<const L: usize> {
    pub x: u8,
    pub y: u8,
    pub z: bool,
}

impl<const L: usize> Ship<L> {
    /**
     * Instantiate a new ship object
     *
     * @param x - x coordinate of ship
     * @param y - y coordinate of ship
     * @param z - orientation of ship
     * @return Ship object
     */
    pub fn new(x: u8, y: u8, z: bool) -> Self {
        Self { x, y, z }
    }

    /**
     * Return the indexes of coordiantes that the ship occupies
     * @notice "index of coordinate" means the serialization of (x, y) into (y * 10 + x)
     * @dev does not provide any checks on coordinate ranges
     *
     * @return array of coordinate indexes occupied by ship placement
     */
    pub fn coordinates(&self) -> [u8; L] {
        let mut coordinates = [0; L];
        for i in 0..L as u8 {
            let x = if self.z { self.x } else { self.x + i };
            let y = if self.z { self.y + i } else { self.y };
            coordinates[i as usize] = y * 10 + x;
        }
        coordinates
    }

    pub fn canonical(&self) -> (u8, u8, bool) {
        (self.x, self.y, self.z)
    }
}
