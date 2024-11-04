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
	Str1 [3]frontend.Variable   `gnark:"str1,secret"`
	Str2 [100]frontend.Variable `gnark:"str2,public"`
}

func (circuit *SubstringCircuit) Define(api frontend.API) error {
	const base = 256  // Base value for hash calculation
	const prime = 101 // A prime number to use for modulus to avoid overflow
	patternLength := len(circuit.Str1)
	textLength := len(circuit.Str2)

	// Helper function to apply modulus with `prime`
	mod := func(a frontend.Variable, prime int64) frontend.Variable {
		primeVar := frontend.Variable(prime)
		for i := 0; i < 5; i++ { // Loop a fixed number of times to simulate modulus reduction
			a = api.Sub(a, api.Mul(primeVar, api.Div(a, primeVar)))
		}
		return a
	}

	// Calculate the hash of the pattern (Str1)
	patternHash := frontend.Variable(0)
	for i := 0; i < patternLength; i++ {
		patternHash = api.Add(api.Mul(patternHash, base), circuit.Str1[i])
		patternHash = mod(patternHash, prime)
	}

	// Calculate the initial hash of the text window of size equal to pattern length
	currentHash := frontend.Variable(0)
	for i := 0; i < patternLength; i++ {
		currentHash = api.Add(api.Mul(currentHash, base), circuit.Str2[i])
		currentHash = mod(currentHash, prime)
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

		// Log intermediate values for debugging
		fmt.Printf("Iteration %d, currentHash: %v, patternHash: %v, isMatch: %v, found: %v\n",
			i, currentHash, patternHash, isMatch, found)

		// Calculate hash for the next window
		if i < textLength-patternLength {
			currentHash = api.Sub(currentHash, api.Mul(circuit.Str2[i], basePow))
			currentHash = api.Mul(currentHash, base)
			currentHash = api.Add(currentHash, circuit.Str2[i+patternLength])
			currentHash = mod(currentHash, prime)
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

func convertToFixedSizeArray100(s []frontend.Variable) [100]frontend.Variable {
	var arr [100]frontend.Variable
	copy(arr[:], s) // Copy elements from the slice to the array
	return arr
}

func main() {
	str1 := [3]frontend.Variable{
		frontend.Variable(97), // 'a'
		frontend.Variable(98), // 'b'
		frontend.Variable(99), // 'c'
	}

	str2s := generateString(100)
	str2 := convertToFixedSizeArray100(str2s)

	var circuit SubstringCircuit
	fmt.Println("Compiling circuit...")
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		log.Fatalf("Circuit compilation failed: %v", err)
	}

	fmt.Println("Setting up Groth16...")
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Fatalf("Setup failed: %v", err)
	}

	assignment := SubstringCircuit{
		Str1: str1,
		Str2: str2,
	}

	fmt.Println("Creating witness...")
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		log.Fatalf("Failed to create witness: %v", err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		log.Fatalf("Failed to create public witness: %v", err)
	}

	fmt.Println("Generating proof...")
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		log.Fatalf("Proof generation failed: %v", err)
	}

	fmt.Println("Verifying proof...")
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		log.Fatalf("Verification failed: %v", err)
	} else {
		fmt.Println("Proof verified successfully")
	}
}
