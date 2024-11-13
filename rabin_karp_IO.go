package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

const (
	maxStr1Len = 70     // Max length for Str1, can be large enough to fit any substring
	maxStr2Len = 500000 // Fixed length for Str2
)

// SubstringCircuit defines the circuit for checking if Str1 is a substring of Str2.
type SubstringCircuit struct {
	Str1            [maxStr1Len]frontend.Variable `gnark:"str1,secret"`
	Str2            [maxStr2Len]frontend.Variable `gnark:"str2,public"`
	EffectiveLength int                           `gnark:"effectiveLength,public"`
}

// Define specifies the logic of the circuit for substring checking.
func (circuit *SubstringCircuit) Define(api frontend.API) error {
	const base = 2
	// const prime = 997
	patternLength := circuit.EffectiveLength
	textLength := len(circuit.Str2)
	// fmt.Println(circuit.EffectiveLength)

	// mod := func(a frontend.Variable, prime int64) frontend.Variable {
	// 	div := api.Div(a, prime)   // Get quotient
	// 	mul := api.Mul(div, prime) // Multiply quotient by prime
	// 	return api.Sub(a, mul)     // Subtract to get remainder
	// }

	// Calculate the hash of the pattern (Str1) until the end marker
	patternHash := frontend.Variable(0)
	for i := 0; i < circuit.EffectiveLength; i++ {
		patternHash = api.Add(api.Mul(patternHash, base), circuit.Str1[i])
		//patternHash = mod(patternHash, prime)
	}

	// Calculate the initial hash of the text window of size equal to pattern length
	currentHash := frontend.Variable(0)
	for i := 0; i < patternLength; i++ {
		currentHash = api.Add(api.Mul(currentHash, base), circuit.Str2[i])
		//currentHash = mod(currentHash, prime)
	}

	// Variable to indicate if we found a matching substring
	found := frontend.Variable(0)

	// Pre-compute base^(patternLength-1) for hash update
	basePow := big.NewInt(1)
	baseBig := big.NewInt(base)
	//primeBig := big.NewInt(prime)
	for i := 0; i < patternLength-1; i++ {
		basePow.Mul(basePow, baseBig) //.Mod(basePow, primeBig)
	}
	basePowVar := frontend.Variable(basePow.Int64())

	// Sliding window to compare hashes incrementally
	for i := 0; i <= textLength-patternLength; i++ {
		isMatch := api.IsZero(api.Sub(currentHash, patternHash))
		found = api.Or(found, isMatch)

		// Debugging: Print current state of the hash comparison
		// fmt.Printf("Debug: Window Position %d - Current Hash: %v, Pattern Hash: %v, Is Match: %v, Found: %v\n", i, currentHash, patternHash, isMatch, found)

		if i < textLength-patternLength {
			currentHash = api.Sub(currentHash, api.Mul(circuit.Str2[i], basePowVar))
			//currentHash = mod(currentHash, prime)
			currentHash = api.Mul(currentHash, base)
			//currentHash = mod(currentHash, prime)
			currentHash = api.Add(currentHash, circuit.Str2[i+patternLength])
			//currentHash = mod(currentHash, prime)
		}
	}

	// Assert that the pattern is found at least once
	api.AssertIsEqual(found, frontend.Variable(1))
	return nil
}

func convertStringToFixedArrayZeroPad(s string) [maxStr1Len]frontend.Variable {
	var arr [maxStr1Len]frontend.Variable
	for i := 0; i < maxStr1Len; i++ {
		if i < len(s) {
			arr[i] = frontend.Variable(int(s[i]))
		} else {
			arr[i] = frontend.Variable(0)
		}

	}

	return arr
}

// Convert a string to a fixed-size array of `frontend.Variable` for Str2
func convertStringToFixedArray(s string, maxLen int) [maxStr2Len]frontend.Variable {
	var arr [maxStr2Len]frontend.Variable
	for i := 0; i < maxLen && i < len(s); i++ {
		arr[i] = frontend.Variable(int(s[i]))
	}
	return arr
}

// Load JSON data from a file and return it as a slice of strings
func loadJSONFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var data []string
	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(bytes, &data); err != nil {
		return nil, err
	}

	return data, nil
}

func main() {
	// Load decoded entries and substrings from JSON files
	decodedEntriesFile := "combined_raw_decoded_entries.json"
	substringsFile := "c-nimbus24_subj-common-names_1000.json"

	decodedEntries, err := loadJSONFile(decodedEntriesFile)
	if err != nil {
		log.Fatalf("Failed to load decoded entries file: %v", err)
	}

	substrings, err := loadJSONFile(substringsFile)
	if err != nil {
		log.Fatalf("Failed to load substrings file: %v", err)
	}

	// Concatenate decoded entries into a single string, truncated to maxStr2Len if necessary
	superLongString := strings.Join(decodedEntries, "")
	if len(superLongString) > maxStr2Len {
		superLongString = superLongString[:maxStr2Len]
	}

	// Convert Str2 to a fixed array
	str2 := convertStringToFixedArray(superLongString, maxStr2Len)
	// fmt.Print(str2)
	// Process each substring in the list
	for _, substring := range substrings {
		if substring == "" {
			continue
		}
		effectiveLen := len(substring)
		// Convert Str1 with end marker
		str1 := convertStringToFixedArrayZeroPad(substring)
		// fmt.Print(str2)
		// fmt.Println(str1)
		// Create the circuit with Str1 and Str2 initialized
		circuit := SubstringCircuit{
			Str1:            str1,
			Str2:            str2,
			EffectiveLength: effectiveLen,
		}

		// Compile the circuit
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
		if err != nil {
			log.Fatalf("Circuit compilation failed: %v", err)
		}

		// Set up Groth16
		pk, vk, err := groth16.Setup(ccs)
		if err != nil {
			log.Fatalf("Setup failed: %v", err)
		}

		// Create witness
		witness := SubstringCircuit{
			Str1: str1,
			Str2: str2,
		}

		witnessInstance, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
		if err != nil {
			log.Fatalf("Failed to create witness for substring '%s': %v", substring, err)
		}

		// Generate proof
		proof, err := groth16.Prove(ccs, pk, witnessInstance)
		if err != nil {
			log.Fatalf("Proof generation failed for substring '%s': %v", substring, err)
		}

		// Verify proof
		publicWitness, err := witnessInstance.Public()
		if err != nil {
			log.Fatalf("Failed to create public witness for substring '%s': %v", substring, err)
		}

		err = groth16.Verify(proof, vk, publicWitness)
		if err != nil {
			fmt.Printf("Verification failed for substring '%s'\n", substring)
		} else {
			fmt.Printf("Proof verified successfully for substring '%s'\n", substring)
		}
	}
}
