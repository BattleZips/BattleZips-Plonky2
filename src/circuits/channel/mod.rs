use plonky2::iop::target::{Target, BoolTarget};

pub mod open_channel;
// pub mod increment_channel;
pub mod close_channel;

pub struct GameTargets {
    // @dev underconstrained without ecc keypairs
    pub host: [Target; 4], // host commitment
    pub guest: [Target; 4], // guest commitment
    pub host_damage: Target, // track hits on host board
    pub guest_damage: Target, // track hits on gues board
    pub turn: BoolTarget, // define the turn order
    pub shot: Target // serialized shot coordinate to check
}