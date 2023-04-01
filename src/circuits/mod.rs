use plonky2::plonk::{
    config::{GenericConfig, PoseidonGoldilocksConfig},
    circuit_data::{CommonCircuitData, VerifierOnlyCircuitData, VerifierCircuitTarget},
    proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget}
};

pub mod board;
pub mod shot;
// pub mod recursion_ex;

pub const D: usize = 2;
pub type C = PoseidonGoldilocksConfig;
pub type F = <C as GenericConfig<D>>::F;

pub type ProofTuple<F, C, const D: usize> = (
    ProofWithPublicInputs<F, C, D>,
    VerifierOnlyCircuitData<C, D>,
    CommonCircuitData<F, D>,
);

pub struct ShieldedTargets {
    pub proof: ProofWithPublicInputsTarget<D>,
    pub verifier: VerifierCircuitTarget,
}