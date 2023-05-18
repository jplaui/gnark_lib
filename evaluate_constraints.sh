#!/bin/sh

echo "\nkdc circuit groth16:"
./gnark_circuits -kdc -iterations 1 -compile
echo "\nkdc circuit plonk:"
./gnark_circuits -kdc -iterations 1 -backend "plonk" -compile

echo "\nauthtag circuit groth16:"
./gnark_circuits -authtag -iterations 1 -compile
echo "\nauthtag circuit plonk:"
./gnark_circuits -authtag -iterations 1 -backend "plonk" -compile

echo "\nrecord circuit groth16:"
./gnark_circuits -record -iterations 1 -compile
echo "\nrecord circuit plonk:"
./gnark_circuits -record -iterations 1 -backend "plonk" -compile

echo "\noracle circuit groth16:"
./gnark_circuits -tls13-oracle -compile
echo "\noracle circuit plonk:"
./gnark_circuits -tls13-oracle -backend "plonk" -compile
