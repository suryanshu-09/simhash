package simhash

import (
	"crypto/md5"
	"log/slog"
	"math/big"
	"os"
	"regexp"
	"strings"
)

// TODO: Simhash Index

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

var (
	DefaultF          = 64
	DefaultHashFunc   = defaultHashFunc
	DefaultLogger     = slog.New(slog.NewTextHandler(os.Stdout, nil))
	batchSize         = 200
	largeWeightCutoff = 50
	DefaultK          = 2
)

func NewSimhash(value any, options ...Option) *Simhash {
	s := &Simhash{
		F:        DefaultF,
		FBytes:   DefaultF / 8,
		HashFunc: DefaultHashFunc,
		Reg:      regexp.MustCompile(`[\p{Han}\p{L}\p{N}_]+`),
		Log:      DefaultLogger,
		Value:    big.NewInt(0),
	}

	for _, opt := range options {
		opt(s)
	}

	if s.F%8 != 0 || s.F == 0 {
		s.Log.Error("f should be a multiple of 8 and not zero\ngot", "f:", s.F)
		s.F = DefaultF
		s.FBytes = s.F / 8
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

type Option func(*Simhash)

func WithF(f int) Option {
	return func(s *Simhash) {
		s.F = f
		s.FBytes = f / 8
	}
}

func WithHashFunc(hashFunc func([]byte) []byte) Option {
	return func(s *Simhash) {
		s.HashFunc = hashFunc
	}
}

func WithRegexPattern(pattern string) Option {
	if pattern != "" {
		return func(s *Simhash) {
			s.Reg = regexp.MustCompile(pattern)
		}
	}
	panic("incorrect regex pattern")
}

func WithLogger(log *slog.Logger) Option {
	return func(s *Simhash) {
		s.Log = log
	}
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
// """
// Don't need it since our newSimhash func already handles various input types for value

func (s *Simhash) buildByFeatures(features map[string]int) *Simhash {
	sums := make([][]int, 0)
	batch := make([][]byte, 0)
	count := 0

	for feature, weight := range features {
		skipBatch := weight > largeWeightCutoff
		count += weight

		hashed := s.HashFunc([]byte(feature))
		h := hashed[len(hashed)-s.FBytes:]

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
		for i := range f {
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
		for i := range f {
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

type Object struct {
	ObjectId string
	S        *Simhash
}

type SimhashIndex struct {
	Obj Object
	F   int
	K   int
	Log *slog.Logger
}

type IndexOptions func(*SimhashIndex)

func SimhashIndexWithF(f int) IndexOptions {
	return func(s *SimhashIndex) {
		s.F = f
	}
}

func SimhashIndexWithK(k int) IndexOptions {
	return func(s *SimhashIndex) {
		s.K = k
	}
}

func SimhashIndexWithLog(log *slog.Logger) IndexOptions {
	return func(s *SimhashIndex) {
		s.Log = log
	}
}

func NewSimhashIndex(objs Object, ixOpt ...IndexOptions) *SimhashIndex {
	s := &SimhashIndex{
		K:   DefaultK,
		F:   DefaultF,
		Log: DefaultLogger,
	}
	return s
}
