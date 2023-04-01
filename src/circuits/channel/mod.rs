use {
    super::RecursiveTargets,
    plonky2::iop::target::{Target, BoolTarget},
};

pub mod open_channel;
pub mod increment_channel;
pub mod close_channel;

pub struct GameTargets {
    // @dev underconstrained without ecc keypairs
    pub prev_proof: RecursiveTargets,
    pub host: [Target; 4], // host commitment
    pub guest: [Target; 4], // guest commitment
    pub host_damage: Target, // track hits on host board
    pub guest_damage: Target, // track hits on gues board
    pub turn: BoolTarget, // define the turn order
    pub shot: Target // serialized shot coordinate to check
}

pub struct GameState {
    pub host: [u64; 4],
    pub guest: [u64; 4],
    pub host_damage: u8,
    pub guest_damage: u8,
    pub turn: bool,
    pub shot: u8
}