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

// EvaluateBezoutCircuit checks that (a(x)*s(x) + b(x)*t(x)) = 1 for given polynomials a,s,b,t and a witness x.
type EvaluateBezoutCircuit struct {
	A []frontend.Variable `gnark:"a,public"` // coefficients of A(x)
	S []frontend.Variable `gnark:"s,public"` // coefficients of S(x)
	B []frontend.Variable `gnark:"b,public"` // coefficients of B(x)
	T []frontend.Variable `gnark:"t,public"` // coefficients of T(x)
	X frontend.Variable   `gnark:"x"`        // witness where we evaluate the polynomials
}

func (c *EvaluateBezoutCircuit) Define(api frontend.API) error {
	// Evaluate a(x)
	aVal := frontend.Variable(0)
	xPow := frontend.Variable(1)
	for i := 0; i < len(c.A); i++ {
		aVal = api.Add(aVal, api.Mul(c.A[i], xPow))
		xPow = api.Mul(xPow, c.X)
	}

	// Evaluate s(x)
	sVal := frontend.Variable(0)
	xPow = frontend.Variable(1)
	for i := 0; i < len(c.S); i++ {
		sVal = api.Add(sVal, api.Mul(c.S[i], xPow))
		xPow = api.Mul(xPow, c.X)
	}

	// Evaluate b(x)
	bVal := frontend.Variable(0)
	xPow = frontend.Variable(1)
	for i := 0; i < len(c.B); i++ {
		bVal = api.Add(bVal, api.Mul(c.B[i], xPow))
		xPow = api.Mul(xPow, c.X)
	}

	// Evaluate t(x)
	tVal := frontend.Variable(0)
	xPow = frontend.Variable(1)
	for i := 0; i < len(c.T); i++ {
		tVal = api.Add(tVal, api.Mul(c.T[i], xPow))
		xPow = api.Mul(xPow, c.X)
	}

	// Compute a(x)*s(x) + b(x)*t(x)
	lhs := api.Add(api.Mul(aVal, sVal), api.Mul(bVal, tVal))

	// Assert (a(x)*s(x) + b(x)*t(x)) = 1
	api.AssertIsEqual(lhs, 1)

	return nil
}

func main() {
	rand.Seed(time.Now().UnixNano())

	// Example degrees:
	degAs := []int{100000, 200000, 300000, 400000, 500000, 600000}
	degBs := []int{100, 200, 400, 800, 1000}

	fmt.Println("degA,degB,time_compile_ms,time_witness_ms,time_total_ms")

	for _, degA := range degAs {
		lenA := degA + 1
		lenS := lenA

		for _, degB := range degBs {
			lenB := degB + 1
			lenT := lenB

			// Generate random coefficients for A,S,B,T
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

			// Generate a random witness x
			x := rand.Int63()

			var circuit EvaluateBezoutCircuit
			circuit.A = append([]frontend.Variable(nil), A...)
			circuit.S = append([]frontend.Variable(nil), S...)
			circuit.B = append([]frontend.Variable(nil), B...)
			circuit.T = append([]frontend.Variable(nil), T...)
			circuit.X = x

			startCompile := time.Now()
			_, err := frontend.Compile(fr.Modulus(), r1cs.NewBuilder, &circuit)
			if err != nil {
				log.Fatal("circuit compilation failed:", err)
			}
			timeCompile := time.Since(startCompile).Milliseconds()

			startWitness := time.Now()
			witness := EvaluateBezoutCircuit{
				A: A,
				S: S,
				B: B,
				T: T,
				X: x,
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
