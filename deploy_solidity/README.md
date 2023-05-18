## Gnark tutorial (groth16 backend)

### Credits
The structure of the repository and tutorial workflow slightly deviates from the workshop repository written by *Gautam Botrel* in his repository [gnark-workshop](https://github.com/gbotrel/gnark-workshop). Here, tooling is updated to latest versions.

### System requirements
- `solc version`
```
solc, the solidity compiler commandline interface
Version: 0.8.17+commit.8df45f5f.Linux.g++
```
- `abigen --version`
```
abigen version 1.10.25-stable-69568c55
```
- `go version`
```
go version go1.19.3 linux/amd64
```
- `ganache --version`
```
ganache v7.5.0 (@ganache/cli: 0.6.0, @ganache/core: 0.6.0)
```
- `npm --version`
```
8.19.3
```

#### Step 1: Installation

Install `solc` solidity compiler and `abigen`, then [application binary interface compiler](https://geth.ethereum.org/docs/dapp/abigen). You can install both tools on a MAC using `brew install geth` or on arch linux with `sudo pacman -S geth solidity`. Optionally, use:
```
git clone https://github.com/ethereum/go-ethereum.git
cd go-ethereum
make devtools
```

Make sure to have [Golang](https://go.dev/doc/install) installed.

Make sure to install Ganache, an Ethereum test network running locally. You can install ganache on you system with `npm i -g ganache`.

In the root folder of this repository, rnu `go mod tidy` once.

#### Step 2: Start the Ethereum test network Ganache

Run the command `ganache -m "much repair shock carbon improve miss forget sock include bullet interest solution"`

(mac only) `ganache-cli -m "much repair shock carbon improve miss forget sock include bullet interest solution"`

By using a *mnemonic* phrase, ganache creates the same accounts on the network. Please use the above mentioned phrase to be compatible with this code version here.

#### Step 3: Compiling a gnark circuit, serializing setup parameters, and exporting a gnark generated solidity verification contract

The first program call to execute is the initialization, which
1. compiles a gnark circuit
2. runs a groth16 setup procedure to generate prover and verifier keys
3. serializes the compiled constraint circuit into a file, serializes the prover and verifier key into files
4. exports a solidity proof verification contract.

The above steps can be achieved by calling `go run main.go -init true`.

#### Step 4: Automatic generation of Golang solidity constract bindings

To generate go bindings for the gnark generated solidity contract which verifies a gnark ZKP on-chain, the contract must be compiled into ABI and BIN files, which is done with the `solc` command. Next, `abigen` uses these files to generate Golang bindings in dedicated Golang packages. The packages created for this tutorial are the `pairings` and `verifier` folders. Only the `verifier` folder will be of interest to be deployed in test network.
By calling `go run main.go -bindings true`, the program calls `solc` and `abigen` to generate all files and bindings such that the solidity contract can be deployed with a transaction.

#### Step 5: Deployment of solidity groth16 zkp verifier contract

Next, before verifying the groth16 ZKP on-chain, the compiled solidity proof verification contract must be deployed to the Ganache test network. To do so, the program connects to the network with one account from the existing list of Ganache accounts. The list of Ganache accounts are displayed in the terminal which is used to run Step 2 of this tutorial. After the nonce, gasprice and gas limits have been set, the contract can be deployed. The command `go run main.go -deploy true` performs the deployment.

*Important*: Make sure to copy the contract address from the terminal logs as you need this hexadecimal number as input to the next program call.

Example output
```
2022/11/09 15:20:16 contract address hex: 0x2e144aF3Bde9B518C7C65FBE170c07c888f1fF1a
2022/11/09 15:20:16 successfully deployed smart contract
```

#### Step 6: Constructing a proof and verifying the proof off-chain and on-chain

Initially the program reads in the serialized form of the compiled constraint system of the groth16 r1cs and deserializes it. Prover and verifier keys copied and deserialized and used to proof and verify the proof in an off-chain manner. The proof is further split up into byte groups such that the proof matches the input requirements of the solidity verification contract. The same happens to the public input of the circuit. Once all input requirements are met, the program calls the verification contract running in the Ganache Ethereum test network. Before calling the contract, the contract must be loaded from the Ganache test network which requires you to enter the contract address as another flag.
The above description is executed when running `go run main.go -address 0x2e144aF3Bde9B518C7C65FBE170c07c888f1fF1a -verify true` (make sure to replace/update the hex address of the contract flag).

#### Step 7:

Stop ganache using ctrl+c.


#### old commands
- `solc --abi mimc_verifier.sol > mimc_verifier.abi`
- `solc --abi mimc_verifier.sol`
- `solc --bin mimc_verifier.sol > mimc_verifier.bin`
- `solc --bin mimc_verifier.sol`
- `solc --abi --bin mimc_verifier.sol -o build`
- `solc --abi mimc_verifier.sol -o build`
- `solc --bin mimc_verifier.sol -o build`
- `abigen --bin=build/Verifier.bin --abi=build/Verifier.abi --pkg=main --out=verifier.go`
- `abigen --bin=build/Pairing.bin --abi=build/Pairing.abi --pkg=main --out=pairing.go`

