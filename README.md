# BattleZips-Plonky2
ZK State Channels FR this time

## TODO
[x] board proof
[x] shot proof
[x] recursive proof
[ ] ecdsa verification of identity
[ ] state channel proof
[ ] post onchain
[ ] efficiency refactor


1. register player 1 board
2. register player 2 board
3. recursively add proofs on top of proofs where hits for each is incremented
4. final recursive proof only generated when = 17 hits, only public output is the winner / loser