package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"flag"
	"io"
	"log"
	"math/big"
	"os"
	"os/exec"

	"groth16_testing/cubic"
	"groth16_testing/verifier"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"

	r1csimport "github.com/consensys/gnark/frontend/cs/r1cs"
)

var (
	fInit     = flag.Bool("init", false, "use go run main.go -init true to compile circuit and srs and store them locally, and export solidity gnark verification contract")
	fBindings = flag.Bool("bindings", false, "use go run main.go -bindings true to compile the solidity proof verification contract and create golang contract bindings")
	fDeploy   = flag.Bool("deploy", false, "use go run main.go -deploy true to deploy the solidity verification contract on-chain")
	fVerify   = flag.Bool("verify", false, "use go run main.go -verify true -address 0x... to verify proof on-chain")
	fAddress  = flag.String("address", "", "use go run main.go -verify true -address 0x... to verify proof on-chain")
)

const (
	r1csPath     = "cubic/cubic.r1cs"
	pkPath       = "cubic/cubic.pk"
	vkPath       = "cubic/cubic.vk"
	solidityPath = "cubic/cubic.sol"
	contractComp = "build/Verifier.abi"
	bindingsPath = "verifier/verifier.go"
)

// main function
func main() {

	// parsing flags
	flag.Parse()

	// check init flag
	if *fInit {
		initCircuit()
		return
	}

	// check if init was performed
	if _, err := os.Stat(r1csPath); os.IsNotExist(err) {
		log.Fatal("you are too early, initially run: go run main.go -init true")
	}

	// check binding flag
	if *fBindings {
		createBindings()
		return
	}

	// check if contract has been compiled
	if _, err := os.Stat(contractComp); os.IsNotExist(err) {
		log.Fatal("compile solidity contract first with: go run main.go -bindings true")
	}

	// check if contract bindings have been generated
	if _, err := os.Stat(bindingsPath); os.IsNotExist(err) {
		log.Fatal("compile solidity contract first with: go run main.go -bindings true")
	}

	// check deployment flag
	if *fDeploy {

		// setup geth simulated backend, deploy smart contract
		verifierContract, err := deploySolidity()
		assertNoError(err)
		log.Println("successfully deployed smart contract")
		_ = verifierContract
		return
	}

	// check verification flag
	if *fVerify {

		log.Println(*fAddress)
		if *fAddress == "" {
			log.Fatal("please specifc the flag: -address 0x...", *fAddress)
		}

		verifyZKP()
		return
	}

}

func createBindings() {

	// compile solidity contract
	// solc --abi --bin cubic/cubic.sol -o build
	cmd := exec.Command("solc", "--overwrite", "--abi", "--bin", "cubic/cubic.sol", "-o", "build")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	assertNoError(err)

	// run abigen to generate go bindings
	// abigen --bin=build/Verifier.bin --abi=build/Verifier.abi --pkg=verifier --out=verifier/verifier.go
	cmd = exec.Command("abigen", "--abi=build/Verifier.abi", "--bin=build/Verifier.bin", "--pkg=verifier", "--out=verifier/verifier.go")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	assertNoError(err)
}

func verifyZKP() {

	client, err := ethclient.Dial("http://localhost:8545")
	if err != nil {
		log.Fatal(err)
	}

	address := common.HexToAddress(*fAddress)
	verifierContract, err := verifier.NewVerifier(address, client)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("verifier contract loaded succesfully")

	// read R1CS, proving key and verifying keys
	r1cs := groth16.NewCS(ecc.BN254)
	pk := groth16.NewProvingKey(ecc.BN254)
	vk := groth16.NewVerifyingKey(ecc.BN254)
	deserialize(r1cs, r1csPath)
	deserialize(pk, pkPath)
	deserialize(vk, vkPath)

	secretInput := 3
	var publicInput int64
	publicInput = 35
	assignment := &cubic.Circuit{
		X: secretInput,
		Y: publicInput,
	}
	witness, _ := frontend.NewWitness(assignment, ecc.BN254)
	publicWitness, _ := witness.Public()
	// pk, vk, err := groth16.Setup(r1cs)

	// create the proof
	log.Println("creating proof")
	proof, err := groth16.Prove(r1cs, pk, witness)
	assertNoError(err)

	// ensure gnark (Go) code verifies it
	log.Println("locally verifying proof")
	err = groth16.Verify(proof, vk, publicWitness)
	assertNoError(err)
	log.Println("successfully verified proof locally")

	// solidity contract inputs
	// a, b and c are the 3 ecc points in the proof we feed to the pairing
	// they are stored in the same order in the golang data structure
	// each coordinate is a field element, of size fp.Bytes bytes
	var (
		a     [2]*big.Int
		b     [2][2]*big.Int
		c     [2]*big.Int
		input [1]*big.Int
	)

	// get proof bytes
	var buf bytes.Buffer
	proof.WriteRawTo(&buf)
	proofBytes := buf.Bytes()

	// proof.Ar, proof.Bs, proof.Krs
	const fpSize = fp.Bytes
	a[0] = new(big.Int).SetBytes(proofBytes[fpSize*0 : fpSize*1])
	a[1] = new(big.Int).SetBytes(proofBytes[fpSize*1 : fpSize*2])
	b[0][0] = new(big.Int).SetBytes(proofBytes[fpSize*2 : fpSize*3])
	b[0][1] = new(big.Int).SetBytes(proofBytes[fpSize*3 : fpSize*4])
	b[1][0] = new(big.Int).SetBytes(proofBytes[fpSize*4 : fpSize*5])
	b[1][1] = new(big.Int).SetBytes(proofBytes[fpSize*5 : fpSize*6])
	c[0] = new(big.Int).SetBytes(proofBytes[fpSize*6 : fpSize*7])
	c[1] = new(big.Int).SetBytes(proofBytes[fpSize*7 : fpSize*8])

	// public witness, the hash of the secret is on chain
	input[0] = big.NewInt(publicInput)

	// call the contract
	log.Println("on-chain verifying proof")
	res, err := verifierContract.VerifyProof(nil, a, b, c, input)
	assertNoError(err)
	if !res {
		log.Fatal("calling the verifier on chain didn't succeed, but should have")
	}
	log.Println("successfully verified proof on-chain")

	// (wrong) public witness
	input[0] = new(big.Int).SetUint64(42)

	// call the contract should fail
	res, err = verifierContract.VerifyProof(nil, a, b, c, input)
	assertNoError(err)
	if res {
		log.Fatal("calling the verifier suceeded, but shouldn't have")
	}
}

func deploySolidity() (*verifier.Verifier, error) {

	client, err := ethclient.Dial("http://localhost:8545")
	if err != nil {
		log.Fatal(err)
	}

	privateKey, err := crypto.HexToECDSA("f1b3f8e0d52caec13491368449ab8d90f3d222a3e485aa7f02591bbceb5efba5")
	if err != nil {
		log.Fatal(err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("error casting public key to ECDSA")
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.Fatal(err)
	}

	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	auth := bind.NewKeyedTransactor(privateKey)
	auth.Nonce = big.NewInt(int64(nonce))
	auth.Value = big.NewInt(0) // in wei
	// auth.GasLimit = uint64(300000) // in units
	auth.GasLimit = uint64(2000000) // in units
	auth.GasPrice = gasPrice

	// deploy verifier contract
	address, tx, verifierContract, err := verifier.DeployVerifier(auth, client)
	if err != nil {
		return nil, err
	}

	log.Println("contract address hex:", address.Hex())
	// log.Println("deployment transaction hash hex:", tx.Hash().Hex())

	_, err = bind.WaitDeployed(context.Background(), client, tx)
	if err != nil {
		log.Fatal("contract deployment failed")
	}

	return verifierContract, nil
}

func initCircuit() {

	_, err := exec.LookPath("abigen")
	if err != nil {
		log.Fatal("please install abigen", err)
	}

	var circuit cubic.Circuit

	// compile circuit
	log.Println("compiling circuit")
	r1cs, err := frontend.Compile(ecc.BN254, r1csimport.NewBuilder, &circuit)
	assertNoError(err)

	// run groth16 trusted setup
	log.Println("running groth16.Setup")
	pk, vk, err := groth16.Setup(r1cs)
	assertNoError(err)

	// serialize R1CS, proving & verifying key
	log.Println("serialize R1CS (circuit)", r1csPath)
	serialize(r1cs, r1csPath)

	log.Println("serialize proving key", pkPath)
	serialize(pk, pkPath)

	log.Println("serialize verifying key", vkPath)
	serialize(vk, vkPath)

	// export verifying key to solidity
	log.Println("export solidity verifier", solidityPath)
	f, err := os.Create(solidityPath)
	assertNoError(err)
	err = vk.ExportSolidity(f)
	assertNoError(err)

}

// serialize gnark object to given file
func serialize(gnarkObject io.WriterTo, fileName string) {
	f, err := os.Create(fileName)
	assertNoError(err)

	_, err = gnarkObject.WriteTo(f)
	assertNoError(err)
}

// deserialize gnark object from given file
func deserialize(gnarkObject io.ReaderFrom, fileName string) {
	f, err := os.Open(fileName)
	assertNoError(err)

	_, err = gnarkObject.ReadFrom(f)
	assertNoError(err)
}

func assertNoError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
