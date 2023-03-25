use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

pub mod place;
pub mod shot;

pub const D: usize = 2;
pub type C = PoseidonGoldilocksConfig;
pub type F = <C as GenericConfig<D>>::F;
