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

type HashFunc func([]byte) []byte

func defaultHashFunction(data []byte) []byte {
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
	defaultF          = 64
	defaultHashFunc   = defaultHashFunction
	defaultLogger     = slog.New(slog.NewTextHandler(os.Stdout, nil))
	batchSize         = 200
	largeWeightCutoff = 50
	defaultK          = 2
)

// Takes in:
// string - then builds by text (slide then tokenise and then build by features)
// map[string]int - already tokenised
// int64 or big.Int - initialise with a value
// Or optional values:
// F - dimension of fingerprints, default 64
// HashFunc - default md5 func([]byte)[]byte
// reg - is meaningful only when `value` is basestring and describes what is considered to be a letter inside parsed string
// logger
func NewSimhash(value any, options ...Option) *Simhash {
	s := &Simhash{
		F:        defaultF,
		FBytes:   defaultF / 8,
		HashFunc: defaultHashFunc,
		Reg:      regexp.MustCompile(`[\p{Han}\p{L}\p{N}_]+`),
		Log:      defaultLogger,
		Value:    big.NewInt(0),
	}

	for _, opt := range options {
		opt(s)
	}

	if s.F%8 != 0 || s.F == 0 {
		s.Log.Error("f should be a multiple of 8 and not zero\ngot", "f:", s.F)
		s.F = defaultF
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

// Find the distance between two simhashes
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

// """
// `objs` is a list of (obj_id, simhash)
// obj_id is a string, simhash is an instance of Simhash
// `f` is the same with the one for Simhash
// `k` is the tolerance
// """
type Object struct {
	ObjectId string
	S        *Simhash
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

type SimhashIndex struct {
	K      int
	F      int
	Log    *slog.Logger
	Bucket map[string]map[string]string
}

func NewSimhashIndex(objs []Object, ixOpt ...IndexOptions) *SimhashIndex {
	s := &SimhashIndex{
		K:      defaultK,
		F:      defaultF,
		Log:    defaultLogger,
		Bucket: map[string]map[string]string{},
	}

	for _, opt := range ixOpt {
		opt(s)
	}

	for _, obj := range objs {
		s.Add(obj)
	}

	return s
}

func (s *SimhashIndex) Add(obj Object) {
	if obj.S == nil || obj.S.F != s.F {
		return
	}
	val := fmt.Sprintf("%x,%s", obj.S.Value, obj.ObjectId)
	for _, key := range s.GetKeys(obj.S) {
		if s.Bucket[key] == nil {
			s.Bucket[key] = make(map[string]string)
		}
		s.Bucket[key][val] = val
	}
}

func (s *SimhashIndex) Delete(obj Object) {
	if obj.S == nil || obj.S.F != s.F {
		return
	}
	val := fmt.Sprintf("%x,%s", obj.S.Value, obj.ObjectId)
	for _, key := range s.GetKeys(obj.S) {
		if _, ok := s.Bucket[key]; ok {
			delete(s.Bucket[key], val)
			if len(s.Bucket[key]) == 0 {
				delete(s.Bucket, key)
			}
		}
	}
}

func (s *SimhashIndex) GetNearDups(simhash *Simhash) []string {
	if simhash.F != s.F {
		return nil
	}

	result := make(map[string]struct{})
	for _, key := range s.GetKeys(simhash) {
		for val := range s.Bucket[key] {
			parts := strings.SplitN(val, ",", 2)
			if len(parts) != 2 {
				continue
			}
			hexVal, objID := parts[0], parts[1]
			hashVal := new(big.Int)
			hashVal.SetString(hexVal, 16)

			dup := &Simhash{Value: hashVal, F: s.F}
			if simhash.Distance(dup) <= s.K {
				result[objID] = struct{}{}
			}
		}
	}

	var ans []string
	for id := range result {
		ans = append(ans, id)
	}
	return ans
}

// from python implementation
//
// """
// You may optimize this method according to <http://static.googleusercontent.com/media/research.google.com/en//pubs/archive/33026.pdf>
// """
func (s *SimhashIndex) GetKeys(sim *Simhash) []string {
	offsets := s.Offsets()
	keys := make([]string, 0, len(offsets))

	for i, offset := range offsets {
		var maskLen int
		if i == len(offsets)-1 {
			maskLen = s.F - offset
		} else {
			maskLen = offsets[i+1] - offset
		}

		mask := new(big.Int).Lsh(big.NewInt(1), uint(maskLen))
		mask.Sub(mask, big.NewInt(1))

		shifted := new(big.Int).Rsh(sim.Value, uint(offset))
		c := new(big.Int).And(shifted, mask)

		keys = append(keys, fmt.Sprintf("%x:%x", c, i))
	}

	return keys
}

func (s *SimhashIndex) Offsets() []int {
	offsets := make([]int, s.K+1)
	chunk := s.F / (s.K + 1)
	for i := 0; i <= s.K; i++ {
		offsets[i] = chunk * i
	}
	return offsets
}

func (s *SimhashIndex) BucketSize() int {
	return len(s.Bucket)
}
