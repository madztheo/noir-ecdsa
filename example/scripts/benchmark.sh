#!/usr/bin/env sh

set -e

run_benchmark() {
  TEST_NAME=$1
  echo $TEST_NAME
  # Run the cargo test and capture the output
  BENCHMARK=$(/usr/bin/time -l cargo test "$TEST_NAME" -- --test-threads=1 2>&1)
  # Extract peak memory (maximum resident set size) from the output
  PEAK_MEM=$(echo "$BENCHMARK" | awk '/maximum resident set size/ {print $1 / 1024 / 1024 " MB"}')
  # Extract the elapsed time (real time) from the output
  SECS_ELAPSED=$(echo "$BENCHMARK" | awk '/real/ {print $1}')
  # Output the results
  echo "Peak memory: $PEAK_MEM"
  echo "Proving time: $SECS_ELAPSED secs"
}

run_benchmark_prove() {
  CIRCUIT=noir_ecdsa_example

  echo "Circuit: $CIRCUIT"

  # Execute the circuit to generate a manifest and witness (< 1s)
  nargo execute ${CIRCUIT}_witness > /dev/null 2>&1

  echo "Generating vkey..."
  # Generate circuit verification key
  bb write_vk_ultra_honk -v -b target/${CIRCUIT}.json -o target/${CIRCUIT}_honk.vkey > /dev/null 2>&1

  echo "Proving..."
  # Run benchmark for proof generation
  BENCHMARK=$(/usr/bin/time -l bb prove_ultra_honk -v -b target/${CIRCUIT}.json -w target/${CIRCUIT}_witness.gz -o ./proofs/${CIRCUIT}_honk.proof 2>&1)

  # Extract peak memory (maximum resident set size) from the output
  PEAK_MEM=$(echo "$BENCHMARK" | awk '/maximum resident set size/ {print $1 / 1024 / 1024 " MB"}')
  # Extract the elapsed time (real time) from the output
  SECS_ELAPSED=$(echo "$BENCHMARK" | awk '/real/ {print $1}')

  # Output the results
  echo "Peak memory: $PEAK_MEM"
  echo "Proving time: $SECS_ELAPSED secs"
}

get_circuit_size() {
  CIRCUIT_SIZE=$(bb gates -b ./target/$1.json -- -h | jq '.functions[0].circuit_size')
  echo "Circuit size: $CIRCUIT_SIZE gates"
}

run_benchmark_prove
