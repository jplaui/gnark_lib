package main

import (
	"bytes"
	"log"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/examples/cubic"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
)

func main() {
	var circuit cubic.Circuit
	//////////// COMPILE ////////////
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	// SERIALIZE - WRITE THE CCS
	var buf bytes.Buffer
	_, _ = ccs.WriteTo(&buf)
	err = os.WriteFile("ccs.dat", buf.Bytes(), 0644)
	if err != nil {
		log.Fatal(err)
	}
	//////////// SETUP ////////////
	// DESERIALIZE - READ THE CCS
	_ccs, err := os.ReadFile("ccs.dat")
	if err != nil {
		log.Fatal(err)
	}
	_buf := *bytes.NewBuffer(_ccs)
	newCCS := plonk.NewCS(ecc.BN254)
	_, _ = newCCS.ReadFrom(&_buf)
	// CREATE SRS
	srs, err := test.NewKZGSRS(ccs)
	if err != nil {
		panic("Failed to create srs: " + err.Error())
	}
	// CREATE PK, VK
	pk, vk, err := plonk.Setup(ccs, srs)
	if err != nil {
		panic("Setup failed!")
	}
	// SERIALIZE - WRITE THE PK & VK
	var bufPK bytes.Buffer
	_, _ = pk.WriteTo(&bufPK)
	err = os.WriteFile("pk.dat", bufPK.Bytes(), 0644)
	if err != nil {
		log.Fatal(err)
	}
	var bufVK bytes.Buffer
	_, _ = vk.WriteTo(&bufVK)
	err = os.WriteFile("vk.dat", bufVK.Bytes(), 0644)
	if err != nil {
		log.Fatal(err)
	}
	//////////// WITNESS ////////////
	w := cubic.Circuit{}
	w.X = 3
	w.Y = 35
	wit, err := frontend.NewWitness(&w, ecc.BN254.ScalarField())
	// Binary marshalling
	data, err := wit.MarshalBinary()
	if err != nil {
		panic("Failed to marshal binary: " + err.Error())
	}
	// SERIALIZE write binary marshalled data to file
	err = os.WriteFile("witness.dat", data, 0644)
	if err != nil {
		panic("Failed to write to file: " + err.Error())
	}
	//////////// PROVE ////////////
	// DESESERIALIZE
	_wit, err := os.ReadFile("witness.dat")
	if err != nil {
		panic("Failed to read from file: " + err.Error())
	}
	_pk, err := os.ReadFile("pk.dat")
	if err != nil {
		panic("Failed to read from file: " + err.Error())
	}
	// Reconstruct witness
	newWitness, _ := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		panic("Failed to create new witness: " + err.Error())
	}
	// Unmarshal Witness
	err = newWitness.UnmarshalBinary(_wit)
	if err != nil {
		panic("Failed to unmarshal binary: " + err.Error())
	}
	newPK := plonk.NewProvingKey(ecc.BN254)
	// Read PK
	_buf = *bytes.NewBuffer(_pk)
	_, err = newPK.ReadFrom(&_buf)
	if err != nil {
		panic("Failed to read prover key: " + err.Error())
	}
	// PROVE
	proof, err := plonk.Prove(newCCS, newPK, newWitness)
	// SESERIALIZE
	// Extract the public part only
	publicWitness, _ := newWitness.Public()
	// Binary marshalling
	data, err = publicWitness.MarshalBinary()
	if err != nil {
		panic("Failed to marshal binary: " + err.Error())
	}
	// SERIALIZE write binary marshalled data to file
	err = os.WriteFile("publicWitness.dat", data, 0644)
	if err != nil {
		panic("Failed to write to file: " + err.Error())
	}
	// Write Proof
	var bufProof bytes.Buffer
	_, _ = proof.WriteTo(&bufProof)
	err = os.WriteFile("proof.dat", bufProof.Bytes(), 0644)
	if err != nil {
		log.Fatal(err)
	}
	//////////// VERIFY ////////////
	// DESERIALIZE
	// Verifier Key
	_vk, err := os.ReadFile("vk.dat")
	if err != nil {
		panic("Failed to read from file: " + err.Error())
	}
	reconstructedVK := plonk.NewVerifyingKey(ecc.BN254)
	// Read VK
	_buf = *bytes.NewBuffer(_vk)
	_, err = reconstructedVK.ReadFrom(&_buf)
	if err != nil {
		panic("Failed to read verifier key: " + err.Error())
	}
	// Public Witness
	_pubWit, err := os.ReadFile("publicWitness.dat")
	if err != nil {
		panic("Failed to read from file: " + err.Error())
	}
	// Extract the public part only
	reconstructedPublicWitness, _ := newWitness.Public()
	// Binary marshalling
	reconstructedPublicWitness.UnmarshalBinary(_pubWit)
	// Proof
	_proof, err := os.ReadFile("proof.dat")
	if err != nil {
		panic("Failed to read from file: " + err.Error())
	}
	reconstructedProof := plonk.NewProof(ecc.BN254)
	_, err = reconstructedProof.ReadFrom(bytes.NewReader(_proof))
	// VERIFY
	err = plonk.Verify(reconstructedProof, reconstructedVK, reconstructedPublicWitness)
	if err != nil {
		panic("Failed Verification!")
	}
}
