# BattleZips-Plonky2
BattleZips-Plonky2 is the culmination of 18 months of R&D on the used of proof-carrying data (PCD) recursion for a novel privacy/ scalability construction. 
Features:
  * Must be a sequential computation at the top level (recursive state channels ("state channels of state channels") allow parallelism, but battleships is an elementary case with no subchannels)
  * Validium-style transaction batching where

## TODO
### Game Proofs 
 - [x] board proof
 - [x] shot proof
 - [x] recursive zk shielding

### State Channel Proofs
 - [x] channel open proof
 - [ ] channel state increment proof 
 - [ ] channel close proof (AKA "ZK State Channel Proof")
 - [ ] example case of full PoC battleship state channel (show the full generation of a ZK State Channel Proof with instant finality)

### EVM Settlement
 - [ ] plonky2-circom wrapping of state channel plonky2 snark proof in a circom groth16 snark proof
 - [ ] refactor [BattleZips chaincode](https://github.com/BattleZips/BattleZips-Circom/blob/master/contracts/BattleshipGame.sol) to settle games in one tx

### Other Improvements
 - [ ] refactor shots to be serialized before input (optional)
 - [ ] refactor board proof to use [BattleZips-Halo2](https://github.com/BattleZips/BattleZips-Halo2) style bitmap comparisons instead of random access gate (optional)
 - [ ] ECC-based identity encryption (required for MVP)
 - [ ] add hash salt to make board commitment computationally binding (required for MVP)
 - [ ] add merkle tree to nullify shot coordinates so they can only be made once per game (required for MVP)
 - [ ] R&D employing a polynomial commitment to make board commitments pefectly hiding (optional)
 - [ ] add utils for reading and writing proof data to buffers for storage in tests/ p2p proof exchange (required for MVP)
 - [ ] add ELO scores to chaincode to demonstrate public quantitative scores from private qualitative state to measure performance (required for MVP)
 - [ ] refactor BattleZips solidity harness from Hardhat to Foundry (optional)


## Steps
### Channel Open Proof
1. host generates a board proof
2. guest generates a board proof
3. host verifies integrity of both board proofs and creates channel open proof with initial game state as "public" outputs
### Channel State Increment Proof
3. recursively add proofs on top of proofs where hits for each is incremented
4. final recursive proof only generated when = 17 hits, only public output is the winner / loser