package main

import (
	"fmt"
	"log"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type SubstringCircuit struct {
	Str1 [3]frontend.Variable       `gnark:"str1,secret"`
	Str2 [1000000]frontend.Variable `gnark:"str2,public"`
}

// func xorComparison(api frontend.API, a, b frontend.Variable) frontend.Variable {
// 	return api.Xor(a, b)
// }

func (circuit *SubstringCircuit) Define(api frontend.API) error {
	found := frontend.Variable(0)

	for i := 0; i <= len(circuit.Str2)-len(circuit.Str1); i++ {
		isMatch := frontend.Variable(1)
		for j := 0; j < len(circuit.Str1); j++ {
			// xorResult := xorComparison(api, circuit.Str1[j], circuit.Str2[i+j])
			// isMatch = api.And(isMatch, api.IsZero(xorResult))

			isMatch = api.IsZero(api.Sub(circuit.Str1[j], circuit.Str2[i+j]))
		}
		found = api.Or(found, isMatch)
	}

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
