package simhash

import (
	"crypto/md5"
	"hash"
	"log/slog"
	"regexp"
	"strings"
)

type Simhash struct {
	Value  uint64
	F      int
	FBytes int
	Reg    *regexp.Regexp
	Hash   hash.Hash
	Log    *slog.Logger
}

func defaultHash() hash.Hash {
	return md5.New()
}

func hashFunc(h hash.Hash, data []byte) []byte {
	h.Reset()
	h.Write(data)
	return h.Sum(nil)
}

var (
	largeWeightCutoff = 50
	batch_size        = 200
)

func NewSimhash(value uint64, f int, reg *regexp.Regexp, hash hash.Hash, log *slog.Logger) *Simhash {
	if f == 0 || f%8 != 0 {
		f = 64
		log.Warn("INCORRECT f VALUE", "f", f)
	}
	fBytes := f / 8

	if reg == nil {
		reg = regexp.MustCompile(`[\w\p{Han}]+`)
		log.Warn("INCORRECT reg VALUE", "reg", reg)
	}
	if hash == nil {
		hash = defaultHash()
		log.Warn("INCORRECT hash VALUE", "hash", hash)
	}

	if log == nil {
		log = slog.Default()
		log.Warn("INCORRECT log VALUE", "log", log)
	}
	return &Simhash{Value: value, F: f, FBytes: fBytes, Reg: reg, Hash: hash, Log: log}
}

func (s *Simhash) Equals(s2 Simhash) bool {
	return s.Value == s2.Value
}

func (s *Simhash) Slide(content string, width int) []string {
	if width <= 0 {
		width = 4
		s.Log.Warn("INCORRECT width VALUE", "width", width)
	}

	runes := []rune(content)
	n := len(runes)
	count := n - width + 1

	count = max(count, 1)

	slideContent := make([]string, 0, count)
	for i := range count {
		end := i + width

		end = min(end, n)
		slice := string(runes[i:end])
		slideContent = append(slideContent, slice)
	}

	return slideContent
}

func (s *Simhash) Tokenise(content string) []string {
	content = strings.ToLower(content)
	matches := s.Reg.FindAllString(content, -1)
	joined := strings.Join(matches, "")
	return s.Slide(joined, 0)
}

func (s *Simhash) BuildByText(content string) {
	features := s.Tokenise(content)
	featuresMap := make(map[string]int)
	for _, feat := range features {
		featuresMap[feat]++
	}
	s.BuildByFeatures(featuresMap)
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

func (s *Simhash) BuildByFeatures(features map[string]int) {
	sums := make([][]int, 0)
	batch := make([][]byte, 0)
	count := 0
	w := 1
	// truncateMask := 1<<s.f - 1

	for feature, weight := range features {
		skipBatch := false

		if weight > largeWeightCutoff {
			skipBatch = true
		}

		count += w
		hashed := hashFunc(s.Hash, []byte(feature))
		h := hashed[:len(hashed)-s.FBytes]

		if skipBatch {
			bitArray := bitArrayFromBytes(h)
			for i := range bitArray {
				bitArray[i] *= w
			}
			sums = append(sums, bitArray)
		} else {
			tempBatch := make([]byte, 0)
			for i, val := range h {
				tempBatch[i] = val * byte(w)
			}
			batch = append(batch, tempBatch)
			if len(batch) >= batch_size {
				sums = append(sums, sumHashes(batch))
				batch = nil
			}
		}
	}
	if batch != nil {
		sums = append(sums, sumHashes(batch))
	}

	combinedSums := make([]int, s.F)
	for _, sum := range sums {
		for i := range s.F {
			combinedSums[i] += sum[i]
		}
	}

	threshold := float64(count) / 2
	bitVector := make([]byte, s.FBytes)
	for i := range s.F {
		if float64(combinedSums[i]) > threshold {
			byteIndex := i / 8
			bitIndex := 7 - (i % 8) // big-endian bit order
			bitVector[byteIndex] |= 1 << bitIndex
		}
	}

	// convert bytes to uint64 (assuming s.f <= 64)
	s.Value = bytesToInt(bitVector)
}

func sumHashes(batch [][]byte) []int {
	if len(batch) == 0 {
		return nil
	}
	length := len(batch[0]) * 8
	sums := make([]int, length)

	for _, hashBytes := range batch {
		bits := bitArrayFromBytes(hashBytes)
		for i := range length {
			sums[i] += bits[i]
		}
	}
	return sums
}

func bitArrayFromBytes(b []byte) []int {
	bits := make([]int, len(b)*8)
	for i, by := range b {
		for bit := range bits {
			// Extract bit from left to right (big-endian bit order)
			// bit 7 = highest bit, bit 0 = lowest bit
			if (by & (1 << (7 - bit))) != 0 {
				bits[i*8+bit] = 1
			} else {
				bits[i*8+bit] = 0
			}
		}
	}
	return bits
}

func (s *Simhash) distance(s2 *Simhash) float64 {
	x := (s.Value ^ s2.Value) & ((1 << s.F) - 1)
	ans := 0.0

	for x > 0 {
		ans++
		x &= x - 1
	}
	return ans
}

func bytesToInt(b []byte) uint64 {
	var val uint64 = 0
	for i := range b {
		val = (val << 8) | uint64(b[i])
	}
	return val
}

func intToBytes(num uint64, length int) []byte {
	b := make([]byte, length)
	for i := length - 1; i >= 0; i-- {
		b[i] = byte(num & 0xff)
		num >>= 8
	}
	return b
}
