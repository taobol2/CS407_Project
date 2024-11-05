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
	Str1 [500]frontend.Variable  `gnark:"str1,secret"`
	Str2 [2000]frontend.Variable `gnark:"str2,public"`
}

func (circuit *SubstringCircuit) Define(api frontend.API) error {
	const base = 256  // Base value for hash calculation
	const prime = 997 // A larger prime number to reduce hash collisions
	patternLength := len(circuit.Str1)
	textLength := len(circuit.Str2)

	// Helper modulus function to reduce value within prime field
	mod := func(a frontend.Variable, prime int64) frontend.Variable {
		div := api.Div(a, prime)   // Get quotient
		mul := api.Mul(div, prime) // Multiply quotient by prime
		return api.Sub(a, mul)     // Subtract to get remainder
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

	// Variable to indicate if we found a matching substring
	found := frontend.Variable(0)

	// Pre-compute base^(patternLength-1) % prime to use for hash update
	basePow := big.NewInt(1)
	baseBig := big.NewInt(base)
	primeBig := big.NewInt(prime)
	for i := 0; i < patternLength-1; i++ {
		basePow.Mul(basePow, baseBig).Mod(basePow, primeBig)
	}
	// Represent the precomputed power as a frontend variable
	basePowVar := frontend.Variable(basePow.Int64())

	// Sliding window to compare hashes
	for i := 0; i <= textLength-patternLength; i++ {
		// If hash matches, do a character-by-character comparison to avoid hash collision false positives
		isMatch := api.IsZero(api.Sub(currentHash, patternHash))
		charMatch := frontend.Variable(1) // Assume true initially

		for j := 0; j < patternLength; j++ {
			charMatch = api.And(charMatch, api.IsZero(api.Sub(circuit.Str2[i+j], circuit.Str1[j])))
		}

		// Only set `found` if both the hash and the character-by-character match succeed
		found = api.Or(found, api.And(isMatch, charMatch))

		// Calculate hash for the next window
		if i < textLength-patternLength {
			// Update hash: remove the first character, shift left, and add the new character
			currentHash = api.Sub(currentHash, api.Mul(circuit.Str2[i], basePowVar))
			currentHash = mod(currentHash, prime)
			currentHash = api.Mul(currentHash, base)
			currentHash = mod(currentHash, prime)
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

func convertToFixedSizeArray2000(s []frontend.Variable) [2000]frontend.Variable {
	var arr [2000]frontend.Variable
	copy(arr[:], s) // Copy elements from the slice to the array
	return arr
}

func convertToFixedSizeArray500(s []frontend.Variable) [500]frontend.Variable {
	var arr [500]frontend.Variable
	copy(arr[:], s) // Copy elements from the slice to the array
	return arr
}

func main() {
	str1s := generateString(500)
	str1 := convertToFixedSizeArray500(str1s)

	str2s := generateString(2000)
	str2 := convertToFixedSizeArray2000(str2s)

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
		fmt.Println("Proof generation failed: Pattern not found in the string.")
		return
	}

	fmt.Println("Verifying proof...")
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Println("Verification failed: Pattern not found in the string.")
	} else {
		fmt.Println("Proof verified successfully: Pattern found in the string.")
	}
}
