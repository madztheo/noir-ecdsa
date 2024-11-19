# Execute the circuit to generate a witness
nargo execute noir_ecdsa_example_witness

# Generate a Honk proof for the circuit with the witness generated just before
time bb prove -b ./target/noir_ecdsa_example.json -w ./target/noir_ecdsa_example_witness.gz -o ./proofs/noir_ecdsa_example_plonk.proof
