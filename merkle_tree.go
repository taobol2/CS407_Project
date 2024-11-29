package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	mimcHash "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"
)

const (
	maxStr1Len  = 70     // Max length for Str1
	maxStr2Len  = 700000 // Fixed length for Str2
	maxProofLen = 30     // Maximum length for Merkle proofs
)

var (
	// Field modulus for BN254
	fieldModulus = fr.Modulus()
)

// SubstringCircuit defines the circuit for verifying the inclusion of a substring via a Merkle proof
type SubstringCircuit struct {
	// Private inputs
	Str1         [maxStr1Len]frontend.Variable  `gnark:"str1,secret"`
	ProofPath    [maxProofLen]frontend.Variable `gnark:"proofPath,secret"`
	ProofPathDir [maxProofLen]frontend.Variable `gnark:"proofPathDir,secret"`
	Masks        [maxProofLen]frontend.Variable `gnark:"masks,secret"`

	// Public inputs
	MerkleRoot frontend.Variable `gnark:"merkleRoot,public"`
}
type ProcessingStats struct {
	TreeBuildTime      time.Duration
	CircuitCompileTime time.Duration
	SetupTime          time.Duration
	TotalProofTime     time.Duration
	VerificationTime   time.Duration
	SuccessfulProofs   int
	FailedProofs       int
	NotFoundPatterns   int
}

// Define the circuit constraints
func (circuit *SubstringCircuit) Define(api frontend.API) error {
	// Initialize MiMC hash function
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// 1. Hash the input pattern
	hFunc.Reset()
	for i := 0; i < maxStr1Len; i++ {
		// Character values are already small, no need for modulo
		hFunc.Write(circuit.Str1[i])
	}
	patternHash := hFunc.Sum()

	// 2. Verify Merkle proof
	currentHash := patternHash

	// Process proof elements
	for i := 0; i < maxProofLen; i++ {
		mask := circuit.Masks[i] // 1 if active, 0 if inactive

		// Prepare the pair to hash
		dirIsZero := api.IsZero(circuit.ProofPathDir[i])
		left := api.Select(dirIsZero, currentHash, circuit.ProofPath[i])
		right := api.Select(dirIsZero, circuit.ProofPath[i], currentHash)

		// Hash the pair
		hFunc.Reset()
		hFunc.Write(left)
		hFunc.Write(right)
		newHash := hFunc.Sum()

		// Update currentHash based on the mask
		deltaHash := api.Sub(newHash, currentHash)
		currentHash = api.Add(currentHash, api.Mul(mask, deltaHash))
	}

	// 3. Check root match
	api.AssertIsEqual(currentHash, circuit.MerkleRoot)

	return nil
}

// MerkleTree represents the Merkle tree for pattern verification
type MerkleTree struct {
	Leaves         []*big.Int
	Nodes          [][]*big.Int
	Root           *big.Int
	PatternToIndex map[string]int // Map from pattern to leaf index
}

// NewMerkleTree constructs a Merkle tree from the given superString and maxPatternLen
func NewMerkleTree(superString string, maxPatternLen int) *MerkleTree {
	fmt.Println("Building Merkle Tree...")
	startTime := time.Now()

	// Generate all possible substrings up to maxPatternLen and remove duplicates
	substrSet := make(map[string]struct{})
	runeSuperString := []rune(superString)
	superStringLen := len(runeSuperString)

	for length := 1; length <= maxPatternLen; length++ {
		for start := 0; start <= superStringLen-length; start++ {
			substrRune := runeSuperString[start : start+length]
			substr := string(substrRune)
			if isURLSubstring(substrRune) {
				substrSet[substr] = struct{}{}
			}
		}
	}

	// Convert set to slice
	var patterns []string
	for substr := range substrSet {
		patterns = append(patterns, substr)
	}

	// Sort the patterns slice to ensure deterministic ordering
	sort.Strings(patterns)

	fmt.Printf("Total unique substrings to hash: %d\n", len(patterns))

	// Convert patterns to leaves and build pattern to index map
	leaves := make([]*big.Int, len(patterns))
	patternToIndex := make(map[string]int)
	for i, pattern := range patterns {
		// Log the pattern being hashed
		// log.Printf("Hashing pattern %d/%d: '%s'", i+1, len(patterns), pattern)

		patternHash := computeHashOffCircuit(pattern)
		leaves[i] = patternHash
		patternToIndex[pattern] = i
		if (i+1)%100000 == 0 || i+1 == len(patterns) {
			fmt.Printf("Hashed %d/%d substrings\n", i+1, len(patterns))
		}
	}

	tree := &MerkleTree{
		Leaves:         leaves,
		PatternToIndex: patternToIndex,
	}
	tree.buildLevels()

	elapsedTime := time.Since(startTime)
	fmt.Printf("Merkle Tree built in %s\n", elapsedTime)

	return tree
}
func (mt *MerkleTree) buildLevels() {
	hFunc := mimcHash.NewMiMC()
	modulus := fr.Modulus()

	currentLevel := mt.Leaves
	mt.Nodes = append(mt.Nodes, currentLevel)

	level := 0
	for len(currentLevel) > 1 {
		nextLevel := make([]*big.Int, (len(currentLevel)+1)/2)
		for i := 0; i < len(currentLevel); i += 2 {
			// First value
			var leftElem fr.Element
			leftElem.SetBigInt(currentLevel[i])

			// Second value (or zero)
			var rightElem fr.Element
			if i+1 < len(currentLevel) {
				rightElem.SetBigInt(currentLevel[i+1])
			} else {
				rightElem.SetZero()
			}

			// Hash the pair
			hFunc.Reset()
			leftBytes := leftElem.Bytes()
			rightBytes := rightElem.Bytes()
			hFunc.Write(leftBytes[:])  // Convert array to slice
			hFunc.Write(rightBytes[:]) // Convert array to slice

			// Reduce result mod field size
			hashBytes := hFunc.Sum(nil)
			hashInt := new(big.Int).SetBytes(hashBytes)
			nextLevel[i/2] = new(big.Int).Mod(hashInt, modulus)
		}
		currentLevel = nextLevel
		mt.Nodes = append(mt.Nodes, currentLevel)
		level++
		fmt.Printf("Built level %d with %d nodes\n", level, len(currentLevel))
	}

	mt.Root = mt.Nodes[len(mt.Nodes)-1][0]
}

func isAllowedURLRune(r rune) bool {
	// Only allow ASCII letters (a-z, A-Z)
	if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
		return true
	}
	// Allow digits (0-9)
	if r >= '0' && r <= '9' {
		return true
	}
	// Allow specific URL-safe special characters
	switch r {
	case '-', '.', '*':
		return true
	default:
		return false
	}
}

// GenerateProof generates a Merkle proof for the given pattern
func (mt *MerkleTree) GenerateProof(pattern string) ([maxProofLen]*big.Int, [maxProofLen]*big.Int, int) {
	var proofPath [maxProofLen]*big.Int
	var proofDir [maxProofLen]*big.Int

	// Initialize all elements with zeros
	for i := 0; i < maxProofLen; i++ {
		proofPath[i] = big.NewInt(0)
		proofDir[i] = big.NewInt(0)
	}

	// Find leaf index using the map
	leafIndex, exists := mt.PatternToIndex[pattern]
	if !exists {
		return proofPath, proofDir, 0
	}

	proofLength := 0
	currentIndex := leafIndex

	// Calculate total tree height (will be consistent for all proofs)
	treeHeight := len(mt.Nodes) - 1 // -1 because leaves level is included

	// Generate proof up to the tree height
	for level := 0; level < treeHeight; level++ {
		siblingIndex := currentIndex ^ 1
		if siblingIndex < len(mt.Nodes[level]) {
			proofPath[level] = mt.Nodes[level][siblingIndex]
			proofDir[level] = big.NewInt(int64(currentIndex % 2))
		}
		proofLength = level + 1 // Always set length to current level + 1
		currentIndex /= 2
	}

	// Fill remaining positions with zeros (should be consistent now)
	for i := proofLength; i < maxProofLen; i++ {
		proofPath[i] = big.NewInt(0)
		proofDir[i] = big.NewInt(0)
	}

	return proofPath, proofDir, proofLength
}

// computeHashOffCircuit computes the MiMC hash of the given pattern
func computeHashOffCircuit(pattern string) *big.Int {
	// Initialize MiMC hash function
	hFunc := mimcHash.NewMiMC()
	hFunc.Reset()

	// Get field modulus
	modulus := fr.Modulus()

	runePattern := []rune(pattern)
	for i := 0; i < maxStr1Len; i++ {
		var val big.Int
		if i < len(runePattern) {
			// Convert character to big.Int and reduce mod field modulus
			val.SetUint64(uint64(runePattern[i]))
			val.Mod(&val, modulus)
		} else {
			val.SetInt64(0)
		}

		// Convert to fr.Element properly
		var elem fr.Element
		elem.SetBigInt(&val)

		// Write element bytes
		bytes := elem.Bytes()
		hFunc.Write(bytes[:])
	}

	// Get hash and reduce mod field size
	hashBytes := hFunc.Sum(nil)
	hashInt := new(big.Int).SetBytes(hashBytes)
	return hashInt.Mod(hashInt, modulus)
}

func isURLSubstring(substr []rune) bool {
	for _, r := range substr {
		if !isAllowedURLRune(r) {
			return false
		}
	}
	return true
}

func main() {
	stats := ProcessingStats{}
	totalStartTime := time.Now()
	// Open the log file
	logFile, err := os.OpenFile("debug.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer logFile.Close()

	// Set log output to the file
	log.SetOutput(logFile)
	// Optional: include timestamps and file info in logs
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Load decoded entries and substrings from JSON files
	decodedEntriesFile := "combined_raw_decoded_entries.json"
	substringsFile := "c-nimbus24_subj-common-names_1000.json"

	decodedEntries, err := loadJSONFile(decodedEntriesFile)
	if err != nil {
		log.Fatalf("Failed to load decoded entries: %v", err)
	}
	log.Printf("Loaded %d decoded entries", len(decodedEntries))

	substrings, err := loadJSONFile(substringsFile)
	if err != nil {
		log.Fatalf("Failed to load substrings: %v", err)
	}
	log.Printf("Loaded %d substrings", len(substrings))

	// Concatenate decoded entries and build Merkle tree
	superString := strings.Join(decodedEntries, "")
	runeSuperString := []rune(superString)
	if len(runeSuperString) > maxStr2Len {
		runeSuperString = runeSuperString[:maxStr2Len]
	}
	superString = string(runeSuperString)

	treeBuildStart := time.Now()
	merkleTree := NewMerkleTree(superString, maxStr1Len)
	stats.TreeBuildTime = time.Since(treeBuildStart)
	fmt.Printf("Merkle Tree built in %s\n", stats.TreeBuildTime)

	// Compile the circuit
	var circuit SubstringCircuit
	compileStart := time.Now()
	fmt.Println("Compiling circuit...")
	ccs, err := frontend.Compile(fieldModulus, r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
	stats.CircuitCompileTime = time.Since(compileStart)
	fmt.Printf("Circuit compiled in %s\n", stats.CircuitCompileTime)

	// Setup proving/verifying keys
	fmt.Println("Setting up proving and verifying keys...")
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}
	fmt.Println("Keys setup completed.")

	// Process each substring
	totalSubstrings := len(substrings)
	fmt.Printf("Processing %d substrings...\n", totalSubstrings)

	proofStartTime := time.Now()
	for idx, substring := range substrings {
		if substring == "" {
			continue
		}

		// Log the substring being processed
		log.Printf("Processing substring %d/%d: '%s'", idx+1, totalSubstrings, substring)

		// if strings.ContainsAny(substring, "-.,:;/?#@!$&*()") {
		// 	fmt.Printf("\nDebug for punctuation-containing string '%s':\n", substring)
		// 	fmt.Printf("Unicode values: ")
		// 	for _, r := range substring {
		// 		fmt.Printf("%d ", r)
		// 	}
		// 	fmt.Printf("\n")

		// 	// Print hash values
		// 	offCircuitHash := computeHashOffCircuit(substring)
		// 	fmt.Printf("Off-circuit hash: %v\n", offCircuitHash)
		// }

		// Generate Merkle proof
		proofPath, proofDir, proofLength := merkleTree.GenerateProof(substring)

		// fmt.Printf("\nproofPath: '%s'", proofPath)
		// fmt.Printf("\nproofDir: '%s'", proofDir)

		// Skip if proof length is zero (substring not found)
		if proofLength == 0 {
			stats.NotFoundPatterns++
			fmt.Printf("\nSubstring '%s' not found in the Merkle tree.\n", substring)
			log.Printf("\nSubstring '%s' not found in the Merkle tree.\n", substring)
			continue
		}

		// Create witness with actual values
		witness := SubstringCircuit{}

		// Handle Unicode characters in substring
		runeSubstring := []rune(substring)
		// Fill in the string values
		for i := 0; i < maxStr1Len; i++ {
			if i < len(runeSubstring) {
				// Use uint64 to match computeHashOffCircuit
				witness.Str1[i] = frontend.Variable(uint64(runeSubstring[i]))
			} else {
				witness.Str1[i] = 0
			}
		}

		// Create Masks array
		for i := 0; i < maxProofLen; i++ {
			if i < proofLength {
				witness.Masks[i] = 1
			} else {
				witness.Masks[i] = 0
			}
		}

		// Convert proof path values to frontend.Variable
		for i := 0; i < maxProofLen; i++ {
			if i < proofLength {
				witness.ProofPath[i] = proofPath[i]
				witness.ProofPathDir[i] = proofDir[i]
			} else {
				witness.ProofPath[i] = 0
				witness.ProofPathDir[i] = 0
			}
		}

		witness.MerkleRoot = merkleTree.Root

		// Create witness instance
		witnessInstance, err := frontend.NewWitness(&witness, fieldModulus)
		if err != nil {
			log.Printf("Failed to create witness for '%s': %v\n", substring, err)
			continue
		}

		// Generate proof
		proof, err := groth16.Prove(ccs, pk, witnessInstance)
		if err != nil {
			log.Printf("Proof generation failed for '%s': %v\n", substring, err)
			continue
		}

		// Verify proof
		publicWitness, err := witnessInstance.Public()
		if err != nil {
			log.Printf("Failed to create public witness for '%s': %v\n", substring, err)
			continue
		}

		verifyStart := time.Now()
		err = groth16.Verify(proof, vk, publicWitness)
		stats.VerificationTime += time.Since(verifyStart)
		if err != nil {
			stats.FailedProofs++
			fmt.Printf("\n❌ Verification failed for substring '%s': %v\n", substring, err)
			log.Printf("Verification failed for substring '%s': %v", substring, err)
		} else {
			stats.SuccessfulProofs++
			fmt.Printf("\n✅ Proof verified successfully for substring '%s'\n", substring)
			log.Printf("Proof verified successfully for substring '%s'", substring)
		}

		// Update progress bar
		printProgressBar(idx+1, totalSubstrings)
	}

	stats.TotalProofTime = time.Since(proofStartTime)

	totalTime := time.Since(totalStartTime)
	fmt.Printf("\n\nFinal Statistics:\n")
	fmt.Printf("Total Time: %s\n", totalTime)
	fmt.Printf("Tree Build Time: %s\n", stats.TreeBuildTime)
	fmt.Printf("Circuit Compilation Time: %s\n", stats.CircuitCompileTime)
	fmt.Printf("Total Proof Generation Time: %s\n", stats.TotalProofTime)
	fmt.Printf("Average Verification Time: %s\n", stats.VerificationTime/time.Duration(stats.SuccessfulProofs+stats.FailedProofs))
	fmt.Printf("Successful Proofs: %d\n", stats.SuccessfulProofs)
	fmt.Printf("Failed Proofs: %d\n", stats.FailedProofs)
	fmt.Printf("Patterns Not Found: %d\n", stats.NotFoundPatterns)
}

// Helper function to load JSON data
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

// Helper function to print a progress bar
func printProgressBar(current, total int) {
	percent := float64(current) / float64(total)
	barLength := 50
	filledLength := int(percent * float64(barLength))

	bar := strings.Repeat("=", filledLength) + strings.Repeat("-", barLength-filledLength)
	fmt.Printf("\rProgress: [%s] %.2f%% (%d/%d)", bar, percent*100, current, total)
}
