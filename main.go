package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/suryanshu-09/simhash/simhash"
)

// tokenizeText splits text into words and returns a map of words with their weights
func tokenizeText(text string) map[string]int {
	// Normalize text: convert to lowercase and remove punctuation
	text = strings.ToLower(text)
	text = strings.ReplaceAll(text, ".", "")
	text = strings.ReplaceAll(text, ",", "")
	text = strings.ReplaceAll(text, "!", "")
	text = strings.ReplaceAll(text, "?", "")
	text = strings.ReplaceAll(text, ";", "")
	text = strings.ReplaceAll(text, ":", "")

	// Split text into words
	words := strings.Fields(text)

	// Create features dictionary with weights
	featuresDict := make(map[string]int)
	for _, word := range words {
		// Increment word count (weight)
		featuresDict[word]++
	}

	return featuresDict
}

func main() {
	// Example texts
	text1 := "This is an example document about simhash algorithm."
	text2 := "This document explains the simhash algorithm with examples."
	text3 := "Completely different text about weather forecast."

	// Tokenize texts into feature dictionaries
	features1 := tokenizeText(text1)
	features2 := tokenizeText(text2)
	features3 := tokenizeText(text3)

	// Calculate simhash for each text
	simhashSize := 64 // 64-bit simhash
	hash1 := simhash.CalculateSimhash(features1, simhashSize, nil)
	hash2 := simhash.CalculateSimhash(features2, simhashSize, nil)
	hash3 := simhash.CalculateSimhash(features3, simhashSize, nil)

	// Print results
	fmt.Printf("Text 1: %s\n", text1)
	fmt.Printf("Text 2: %s\n", text2)
	fmt.Printf("Text 3: %s\n", text3)
	fmt.Println()

	fmt.Printf("Simhash 1: %016x\n", hash1)
	fmt.Printf("Simhash 2: %016x\n", hash2)
	fmt.Printf("Simhash 3: %016x\n", hash3)
	fmt.Println()

	// Calculate similarities
	sim12 := simhash.Similarity(hash1, hash2)
	sim13 := simhash.Similarity(hash1, hash3)
	sim23 := simhash.Similarity(hash2, hash3)

	fmt.Printf("Similarity between Text 1 and Text 2: %.4f\n", sim12)
	fmt.Printf("Similarity between Text 1 and Text 3: %.4f\n", sim13)
	fmt.Printf("Similarity between Text 2 and Text 3: %.4f\n", sim23)

	// Calculate Hamming distances
	dist12 := simhash.HammingDistance(hash1, hash2)
	dist13 := simhash.HammingDistance(hash1, hash3)
	dist23 := simhash.HammingDistance(hash2, hash3)

	fmt.Printf("Hamming distance between Text 1 and Text 2: %d bits\n", dist12)
	fmt.Printf("Hamming distance between Text 1 and Text 3: %d bits\n", dist13)
	fmt.Printf("Hamming distance between Text 2 and Text 3: %d bits\n", dist23)

	// Demonstrating packing to bytes
	bytes1 := simhash.PackSimhashToBytes(hash1, simhashSize)
	log.Printf("Simhash 1 packed to %d bytes\n", len(bytes1))
}

