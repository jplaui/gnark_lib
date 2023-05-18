#!/bin/sh

## tls specific circuits
echo "\nkdc circuit groth16:"
./gnark_circuits -kdc -iterations 1
echo "\nkdc circuit plonk:"
./gnark_circuits -kdc -iterations 1 -backend "plonk"

echo "\nauthtag circuit groth16:"
./gnark_circuits -authtag -iterations 1
echo "\nauthtag circuit plonk:"
./gnark_circuits -authtag -iterations 1 -backend "plonk"

echo "\nrecord circuit groth16:"
./gnark_circuits -record -iterations 1
echo "\nrecord circuit plonk:"
./gnark_circuits -record -iterations 1 -backend "plonk"

echo "\noracle circuit groth16:"
./gnark_circuits -tls13-oracle -iterations 1
echo "\noracle circuit plonk:"
./gnark_circuits -tls13-oracle -iterations 1 -backend "plonk"

## basic circuits
echo "\nshacal2 circuit groth16:"
./gnark_circuits -shacal2 -iterations 2

echo "\naes128 circuit groth16:"
./gnark_circuits -aes128 -iterations 2

echo "\nsubstring circuit groth16:"
./gnark_circuits -substring -iterations 2

echo "\nstr2int circuit groth16:"
./gnark_circuits -str2int -iterations 2

echo "\nstr2int circuit groth16:"
./gnark_circuits -str2int -iterations 2

echo "\ngtlt circuit groth16:"
./gnark_circuits -gtlt -iterations 2

## dynamic circuits
echo "\ngcm dynamic circuit groth16:"
./gnark_circuits -gcm -iterations 2 -byte-size 16
echo "\ngcm dynamic circuit groth16:"
./gnark_circuits -gcm -iterations 2 -byte-size 32
echo "\ngcm dynamic circuit plonk:"
./gnark_circuits -gcm -iterations 2 -byte-size 16 -backend "plonk"
echo "\ngcm dynamic circuit plonk:"
./gnark_circuits -gcm -iterations 2 -byte-size 32 -backend "plonk"

echo "\nsha256 dynamic circuit groth16:"
./gnark_circuits -sha256 -iterations 2 -byte-size 32

echo "\nxor dynamic circuit groth16:"
./gnark_circuits -xor -iterations 2 -byte-size 16

