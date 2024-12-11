package main

import (
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type EvaluateAtOneCircuit struct {
	A []frontend.Variable `gnark:"a,public"`
	S []frontend.Variable `gnark:"s,public"`
	B []frontend.Variable `gnark:"b,public"`
	T []frontend.Variable `gnark:"t,public"`
}

func (c *EvaluateAtOneCircuit) Define(api frontend.API) error {
	nA := len(c.A)
	nB := len(c.B)

	// Initialize sums with the first coefficient
	aSum := c.A[0]
	for i := 1; i < nA; i++ {
		aSum = api.Add(aSum, c.A[i])
	}

	sSum := c.S[0]
	for i := 1; i < nA; i++ {
		sSum = api.Add(sSum, c.S[i])
	}

	bSum := c.B[0]
	for i := 1; i < nB; i++ {
		bSum = api.Add(bSum, c.B[i])
	}

	tSum := c.T[0]
	for i := 1; i < nB; i++ {
		tSum = api.Add(tSum, c.T[i])
	}

	// (aSum*sSum) + (bSum*tSum)
	lhs := api.Add(api.Mul(aSum, sSum), api.Mul(bSum, tSum))

	// lhs must equal 1
	api.AssertIsEqual(lhs, 1)

	return nil
}

func NextPowerOfTwo(n int) int {
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}

func main() {
	rand.Seed(time.Now().UnixNano())

	degAs := []int{100000, 200000, 300000, 400000, 500000, 600000}
	degBs := []int{100, 200, 400, 800, 1000}

	fmt.Println("degA,degB,time_compile_ms,time_witness_ms,time_total_ms")

	for _, degA := range degAs {
		lenA := degA + 1
		lenS := lenA

		for _, degB := range degBs {
			lenB := degB + 1
			lenT := lenB

			A := make([]frontend.Variable, lenA)
			S := make([]frontend.Variable, lenS)
			B := make([]frontend.Variable, lenB)
			T := make([]frontend.Variable, lenT)

			for i := 0; i < lenA; i++ {
				A[i] = rand.Int63()
				S[i] = rand.Int63()
			}
			for i := 0; i < lenB; i++ {
				B[i] = rand.Int63()
				T[i] = rand.Int63()
			}

			var circuit EvaluateAtOneCircuit
			circuit.A = make([]frontend.Variable, lenA)
			circuit.S = make([]frontend.Variable, lenS)
			circuit.B = make([]frontend.Variable, lenB)
			circuit.T = make([]frontend.Variable, lenT)
			copy(circuit.A, A)
			copy(circuit.S, S)
			copy(circuit.B, B)
			copy(circuit.T, T)

			startCompile := time.Now()
			ccs, err := frontend.Compile(fr.Modulus(), r1cs.NewBuilder, &circuit)
			if err != nil {
				log.Fatal("circuit compilation failed:", err)
			}
			timeCompile := time.Since(startCompile).Milliseconds()

			// Use ccs to avoid declared and not used error
			nbConstraints := ccs.GetNbConstraints()
			_ = nbConstraints // We won't print it to keep output clean, but now ccs is used.

			startWitness := time.Now()
			witness := EvaluateAtOneCircuit{
				A: A,
				S: S,
				B: B,
				T: T,
			}
			_, err = frontend.NewWitness(&witness, fr.Modulus())
			if err != nil {
				log.Fatal("Failed to create witness:", err)
			}
			timeWitness := time.Since(startWitness).Milliseconds()

			timeTotal := timeCompile + timeWitness

			fmt.Printf("%d,%d,%d,%d,%d\n", degA, degB, timeCompile, timeWitness, timeTotal)
		}
	}
}
