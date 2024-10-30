package main

import (
	"fmt"
	"log"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type SubstringCircuit struct {
	Str1 [3]frontend.Variable       `gnark:"str1,secret"`
	Str2 [1000000]frontend.Variable `gnark:"str2,public"`
}

func (circuit *SubstringCircuit) Define(api frontend.API) error {
	const base = 256  // Base value for hash calculation
	const prime = 101 // A prime number to use for modulus to avoid overflow
	patternLength := len(circuit.Str1)
	textLength := len(circuit.Str2)

	// Calculate the hash of the pattern (Str1)
	patternHash := frontend.Variable(0)
	for i := 0; i < patternLength; i++ {
		patternHash = api.Add(api.Mul(patternHash, base), circuit.Str1[i])
		patternHash = api.Add(patternHash, prime) // Simple modulus operation replacement
	}

	// Calculate the initial hash of the text window of size equal to pattern length
	currentHash := frontend.Variable(0)
	for i := 0; i < patternLength; i++ {
		currentHash = api.Add(api.Mul(currentHash, base), circuit.Str2[i])
		currentHash = api.Add(currentHash, prime) // Simple modulus operation replacement
	}

	found := frontend.Variable(0)
	basePow := big.NewInt(1)
	baseBig := big.NewInt(base)
	primeBig := big.NewInt(prime)
	for i := 0; i < patternLength-1; i++ {
		basePow.Mul(basePow, baseBig).Mod(basePow, primeBig)
	}

	// Sliding window to compare hashes
	for i := 0; i <= textLength-patternLength; i++ {
		// Compare hash values
		isMatch := api.IsZero(api.Sub(currentHash, patternHash))
		found = api.Or(found, isMatch)

		// Calculate hash for the next window
		if i < textLength-patternLength {
			currentHash = api.Sub(currentHash, api.Mul(circuit.Str2[i], basePow))
			currentHash = api.Mul(currentHash, base)
			currentHash = api.Add(currentHash, circuit.Str2[i+patternLength])
			currentHash = api.Add(currentHash, prime) // Simple modulus operation replacement
		}
	}

	// Assert that the pattern is found at least once
	api.AssertIsEqual(found, frontend.Variable(1))

	return nil
}

func generateString(N int) []frontend.Variable {
	pattern := []frontend.Variable{
		frontend.Variable(120), // 'x'
		frontend.Variable(120), // 'x'
		frontend.Variable(97),  // 'a'
		frontend.Variable(98),  // 'b'
		frontend.Variable(99),  // 'c'
		frontend.Variable(120), // 'x'
		frontend.Variable(120), // 'x'
	}

	result := make([]frontend.Variable, 0, N)
	for len(result) < N {
		if len(result)+len(pattern) <= N {
			result = append(result, pattern...)
		} else {
			result = append(result, pattern[:N-len(result)]...)
		}
	}
	return result
}

func convertToFixedSizeArray1000000(s []frontend.Variable) [1000000]frontend.Variable {
	var arr [1000000]frontend.Variable
	copy(arr[:], s) // Copy elements from the slice to the array
	return arr
}

func main() {
	str1 := [3]frontend.Variable{
		frontend.Variable(97),
		frontend.Variable(98),
		frontend.Variable(99),
	}

	str2s := generateString(1000000)
	str2 := convertToFixedSizeArray1000000(str2s)
	var circuit SubstringCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		log.Fatalf("Circuit compilation failed: %v", err)
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Fatalf("Setup failed: %v", err)
	}

	assignment := SubstringCircuit{
		Str1: str1,
		Str2: str2,
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		log.Fatalf("Failed to create witness: %v", err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		log.Fatalf("Failed to create public witness: %v", err)
	}

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		log.Fatalf("Proof generation failed: %v", err)
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		log.Fatalf("Verification failed: %v", err)
	} else {
		fmt.Println("Proof verified successfully")
	}
}
