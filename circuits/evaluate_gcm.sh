## dynamic circuits
echo "\ngcm dynamic circuit groth16:"
./circuits -gcm -iterations 1 -byte-size 16
echo "\ngcm dynamic circuit groth16:"
./circuits -gcm -iterations 1 -byte-size 32
echo "\ngcm dynamic circuit groth16:"
./circuits -gcm -iterations 1 -byte-size 64
echo "\ngcm dynamic circuit groth16:"
./circuits -gcm -iterations 1 -byte-size 128
echo "\ngcm dynamic circuit groth16:"
./circuits -gcm -iterations 1 -byte-size 256
echo "\ngcm dynamic circuit groth16:"
./circuits -gcm -iterations 1 -byte-size 512
echo "\ngcm dynamic circuit groth16:"
./circuits -gcm -iterations 1 -byte-size 1024

echo "\ngcm dynamic circuit plonk:"
./circuits -gcm -iterations 1 -byte-size 16 -backend "plonk"
echo "\ngcm dynamic circuit plonk:"
./circuits -gcm -iterations 1 -byte-size 32 -backend "plonk"
echo "\ngcm dynamic circuit plonk:"
./circuits -gcm -iterations 1 -byte-size 64 -backend "plonk"
echo "\ngcm dynamic circuit plonk:"
./circuits -gcm -iterations 1 -byte-size 128 -backend "plonk"
echo "\ngcm dynamic circuit plonk:"
./circuits -gcm -iterations 1 -byte-size 256 -backend "plonk"
echo "\ngcm dynamic circuit plonk:"
./circuits -gcm -iterations 1 -byte-size 512 -backend "plonk"
echo "\ngcm dynamic circuit plonk:"
./circuits -gcm -iterations 1 -byte-size 1024 -backend "plonk"
