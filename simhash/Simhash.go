package simhash

import (
	"crypto/md5"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"regexp"
	"strings"
)

// TODO:BUILD BY TEXT and BUILD BY FEATURES (batches + go routines)

var (
	largeWeightCutoff = 50
	batchSize         = 200
)

type HashFunc func([]byte) []byte

func defaultHashFunc(data []byte) []byte {
	hash := md5.Sum(data)
	return hash[:]
}

type Simhash struct {
	Value    *big.Int
	F        int
	FBytes   int
	Reg      *regexp.Regexp
	HashFunc HashFunc
	Log      *slog.Logger
}

type NewSimhashOptions struct {
	F        int
	FBytes   int
	Reg      *regexp.Regexp
	HashFunc HashFunc
	Log      *slog.Logger
}

func NewSimhash(value any, f int, regPattern string, hashFunc HashFunc, logger *slog.Logger) *Simhash {
	if f%8 != 0 || f == 0 {
		f = 64
		fmt.Printf("f should not be 0 and divisible by 8\ngot:%d\n", f)
	}

	if hashFunc == nil {
		hashFunc = defaultHashFunc
	}

	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stdout, nil))
	}

	var reg *regexp.Regexp
	var err error
	if regPattern == "" {
		reg = regexp.MustCompile(`[\p{Han}\p{L}\p{N}_]+`)
	} else {
		reg, err = regexp.Compile(regPattern)
		if err != nil {
			fmt.Printf("Invalid regex pattern, falling back to default:\n%s\n", err)
			reg = regexp.MustCompile(`[\p{Han}\p{L}\p{N}_]+`)
		}
	}

	s := &Simhash{
		F:        f,
		FBytes:   f / 8,
		Reg:      reg,
		HashFunc: hashFunc,
		Log:      logger,
		Value:    big.NewInt(0),
	}

	switch v := value.(type) {
	case *Simhash:
		s.Value.Set(v.Value)
	case string:
		return s.buildByText(v)
	case map[string]int:
		return s.buildByFeatures(v)
	case []string:
		features := make(map[string]int)
		for _, feature := range v {
			features[feature] = 1
		}
		return s.buildByFeatures(features)
	case int64:
		s.Value.SetInt64(v)
	case *big.Int:
		s.Value.Set(v)
	default:
		return nil
	}

	return s
}

func (s *Simhash) Equal(s2 *Simhash) bool {
	return s.Value.Cmp(s2.Value) == 0
}

func (s *Simhash) slide(content string, width int) []string {
	if len(content) < width {
		return []string{content}
	}

	result := make([]string, 0, len(content)-width+1)
	for i := 0; i <= len(content)-width; i++ {
		result = append(result, content[i:i+width])
	}
	return result
}

func (s *Simhash) tokenize(content string) []string {
	content = strings.ToLower(content)
	matches := s.Reg.FindAllString(content, -1)
	content = strings.Join(matches, "")

	return s.slide(content, 4)
}

func (s *Simhash) buildByText(content string) *Simhash {
	features := s.tokenize(content)

	featureMap := make(map[string]int)
	for _, feature := range features {
		featureMap[feature]++
	}

	return s.buildByFeatures(featureMap)
}

// from python implementation
//
// """
// `features` might be a list of unweighted tokens (a weight of 1
//
//	will be assumed), a list of (token, weight) tuples or
//	a token -> weight dict.
//
// NO NEED SINCE THE FUNCTION IMPLEMENTATION ONLY RETURNS map[string]int
//
// IF STILL NEED DEFINE AN INTERFACE LIKE
// type buildByFeaturesInterface interface{
// ~[]string | ~ map[string]int | featureStruct
// }
//
//	type featureStruct struct{
//		token []string
//		weight []int
//	}
//
//	AND DO TYPE CHECKING IN THE FUNCTION LIKE:
//
//	switch v := any(features).(type)
//
// """

// func (s *Simhash) buildByFeatures(features map[string]int) *Simhash {
// 	v := make([]int, s.F)
//
// 	for feature, weight := range features {
// 		hashBytes := s.HashFunc([]byte(feature))
//
// 		if len(hashBytes) > s.FBytes {
// 			hashBytes = hashBytes[len(hashBytes)-s.FBytes:]
// 		}
//
// 		for i := 0; i < len(hashBytes) && i < s.FBytes; i++ {
// 			for j := range 8 {
// 				bitIndex := i*8 + j
// 				if bitIndex < s.F {
// 					if hashBytes[i]&(1<<(7-j)) != 0 {
// 						v[bitIndex] += weight
// 					} else {
// 						v[bitIndex] -= weight
// 					}
// 				}
// 			}
// 		}
// 	}
//
// 	var result []byte
// 	for i := 0; i < s.F; i += 8 {
// 		var b byte
// 		for j := 0; j < 8 && i+j < s.F; j++ {
// 			if v[i+j] > 0 {
// 				b |= 1 << (7 - j)
// 			}
// 		}
// 		result = append(result, b)
// 	}
//
// 	s.Value.SetBytes(result)
// 	return s
// }

func (s *Simhash) buildByFeatures(features map[string]int) *Simhash {
	sums := make([][]int, 0)
	batch := make([][]byte, 0)
	count := 0

	for feature, weight := range features {
		skipBatch := weight > largeWeightCutoff
		count += weight

		hashed := s.HashFunc([]byte(feature)) // full hash
		h := hashed[len(hashed)-s.FBytes:]    // truncated hash

		if skipBatch {
			bitArray := bitArrayFromBytes(h)
			weightedArray := make([]int, len(bitArray))
			for i, bit := range bitArray {
				weightedArray[i] = bit * weight
			}
			sums = append(sums, weightedArray)
		} else {
			for range weight {
				batch = append(batch, h)
			}

			if len(batch) >= batchSize {
				sums = append(sums, sumHashes(batch, s.F))
				batch = make([][]byte, 0)
			}
		}

		if len(sums) >= batchSize {
			sums = [][]int{sumHashesBytes(sums)}
		}
	}

	if len(batch) > 0 {
		sums = append(sums, sumHashes(batch, s.F))
	}

	combinedSums := sumHashesBytes(sums)

	// Bit thresholding
	finalBits := make([]int, len(combinedSums))
	for i, val := range combinedSums {
		if val > count/2 {
			finalBits[i] = 1
		}
	}

	s.Value.SetBytes(packBits(finalBits))
	return s
}

func bitArrayFromBytes(hash []byte) []int {
	bitArray := make([]int, 0, len(hash)*8)
	for _, b := range hash {
		for i := 7; i >= 0; i-- {
			bit := (b >> i) & 1
			bitArray = append(bitArray, int(bit))
		}
	}
	return bitArray
}

func sumHashes(digests [][]byte, f int) []int {
	bitMatrix := make([][]int, len(digests))
	for i, d := range digests {
		bitMatrix[i] = bitArrayFromBytes(d)
	}
	summed := make([]int, f)
	for _, bits := range bitMatrix {
		for i := 0; i < f; i++ {
			summed[i] += bits[i]
		}
	}
	return summed
}

func sumHashesBytes(sums [][]int) []int {
	if len(sums) == 0 {
		return nil
	}
	f := len(sums[0])
	total := make([]int, f)
	for _, row := range sums {
		for i := 0; i < f; i++ {
			total[i] += row[i]
		}
	}
	return total
}

func packBits(bits []int) []byte {
	n := (len(bits) + 7) / 8
	result := make([]byte, n)
	for i, bit := range bits {
		if bit != 0 {
			byteIndex := i / 8
			bitIndex := 7 - (i % 8)
			result[byteIndex] |= 1 << bitIndex
		}
	}
	return result
}

func (s *Simhash) Distance(other *Simhash) int {
	if s.F != other.F {
		panic("simhashes must have same dimensions")
	}

	xor := new(big.Int).Xor(s.Value, other.Value)

	mask := new(big.Int).Lsh(big.NewInt(1), uint(s.F))
	mask.Sub(mask, big.NewInt(1))
	xor.And(xor, mask)

	count := 0
	for xor.Sign() > 0 {
		count++
		temp := new(big.Int).Sub(xor, big.NewInt(1))
		xor.And(xor, temp)
	}

	return count
}
