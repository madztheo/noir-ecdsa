# Compile the circuit and get the number of the gates
nargo compile --force && bb gates -b ./target/noir_ecdsa_example.json > ./info/noir_ecdsa_example.json
