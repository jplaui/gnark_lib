#!/bin/sh

echo "\nkdc circuit groth16:"
./circuits -kdc -iterations 1 -compile
echo "\nkdc circuit plonk:"
./circuits -kdc -iterations 1 -backend "plonk" -compile

echo "\nauthtag circuit groth16:"
./circuits -authtag -iterations 1 -compile
echo "\nauthtag circuit plonk:"
./circuits -authtag -iterations 1 -backend "plonk" -compile

echo "\nrecord circuit groth16:"
./circuits -record -iterations 1 -compile
echo "\nrecord circuit plonk:"
./circuits -record -iterations 1 -backend "plonk" -compile

echo "\noracle circuit groth16:"
./circuits -tls13-oracle -compile -iterations 1
echo "\noracle circuit plonk:"
./circuits -tls13-oracle -backend "plonk" -iterations 1 -compile
