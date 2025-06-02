package tests

import (
	"crypto/md5"
	"crypto/sha256"
	"math/big"
	"strconv"
	"testing"

	s "github.com/suryanshu-09/simhash/simhash"
)

func TestIntValue(t *testing.T) {
	tests := []struct {
		input    int64
		expected int64
	}{
		{0, 0},
		{4390059585430954713, 4390059585430954713},
	}

	for _, test := range tests {
		sh := s.NewSimhash(test.input, 64, "", nil, nil)
		if sh.Value.Int64() != test.expected {
			t.Errorf("Expected %d, got %d", test.expected, sh.Value.Int64())
		}
	}

	largeNum := new(big.Int)
	largeNum.SetString("9223372036854775808", 10)
	sh := s.NewSimhash(largeNum, 64, "", nil, nil)
	if sh.Value.Cmp(largeNum) != 0 {
		t.Errorf("Expected %s, got %s", largeNum.String(), sh.Value.String())
	}
}

func TestValue(t *testing.T) {
	features := []string{"aaa", "bbb"}
	sh := s.NewSimhash(features, 64, "", nil, nil)

	if sh.Value.Sign() == 0 {
		t.Error("Simhash value should not be zero for non-empty features")
	}

	sh2 := s.NewSimhash(features, 64, "", nil, nil)

	if sh.Value.Cmp(sh2.Value) != 0 {
		t.Error("Same input should produce same simhash value")
	}
}

func TestDistance(t *testing.T) {
	sh := s.NewSimhash("How are you? I AM fine. Thanks. And you?", 64, "", nil, nil)

	sh2 := s.NewSimhash("How old are you ? :-) i am fine. Thanks. And you?", 64, "", nil, nil)

	distance := sh.Distance(sh2)
	if distance == 0 {
		t.Error("Distance should be greater than 0 for different texts")
	}

	sh3 := s.NewSimhash(sh2, 64, "", nil, nil)

	if sh2.Distance(sh3) != 0 {
		t.Error("Distance should be 0 for identical simhashes")
	}

	sh4 := s.NewSimhash("1", 64, "", nil, nil)

	sh5 := s.NewSimhash("2", 64, "", nil, nil)

	if sh4.Distance(sh5) == 0 {
		t.Error("Distance should not be 0 for different strings")
	}
}

func TestChinese(t *testing.T) {
	sh1 := s.NewSimhash("你好　世界！　　呼噜。", 64, "", nil, nil)

	sh2 := s.NewSimhash("你好，世界　呼噜", 64, "", nil, nil)

	sh4 := s.NewSimhash("How are you? I Am fine. ablar ablar xyz blar blar blar blar blar blar blar Thanks.", 64, "", nil, nil)

	sh5 := s.NewSimhash("How are you i am fine.ablar ablar xyz blar blar blar blar blar blar blar than", 64, "", nil, nil)

	sh6 := s.NewSimhash("How are you i am fine.ablar ablar xyz blar blar blar blar blar blar blar thank", 64, "", nil, nil)

	chineseDistance := sh1.Distance(sh2)
	t.Logf("Chinese distance: %d", chineseDistance)

	if sh4.Distance(sh6) >= 10 {
		t.Error("Distance between similar English texts should be small")
	}

	if sh5.Distance(sh6) >= 10 {
		t.Error("Distance between similar English texts should be small")
	}
}

func TestShort(t *testing.T) {
	texts := []string{"aa", "aaa", "aaaa", "aaaab", "aaaaabb", "aaaaabbb"}
	var simhashes []*big.Int

	for _, text := range texts {
		sh := s.NewSimhash(text, 64, "", nil, nil)
		simhashes = append(simhashes, new(big.Int).Set(sh.Value))
	}

	for i, sh1 := range simhashes {
		for j, sh2 := range simhashes {
			if i != j && sh1.Cmp(sh2) == 0 {
				t.Errorf("Simhashes for '%s' and '%s' should be different", texts[i], texts[j])
			}
		}
	}
}

func TestEqualityComparison(t *testing.T) {
	a := s.NewSimhash("My name is John", 64, "", nil, nil)

	b := s.NewSimhash("My name is John", 64, "", nil, nil)

	c := s.NewSimhash("My name actually is Jane", 64, "", nil, nil)

	if !a.Equal(b) {
		t.Error("A should equal B")
	}

	if a.Equal(c) {
		t.Error("A should not equal C")
	}
}

func TestCustomHashFunc(t *testing.T) {
	intHashFunc := func(x []byte) []byte {
		hash := md5.Sum(x)
		hashInt := new(big.Int).SetBytes(hash[:])
		return hashInt.Bytes()
	}

	shaHashFunc := func(x []byte) []byte {
		hash := sha256.Sum256(x)
		return hash[:]
	}

	a := s.NewSimhash("My name is John", 64, "", nil, nil)

	b := s.NewSimhash("My name is John", 64, "", intHashFunc, nil)

	c := s.NewSimhash("My name is John", 64, "", shaHashFunc, nil)

	t.Logf("Default hash: %x", a.Value)
	t.Logf("Int hash: %x", b.Value)
	t.Logf("SHA hash: %x", c.Value)

	if a.Equal(c) {
		t.Error("Different hash functions should produce different results")
	}
}

func TestLargeInputs(t *testing.T) {
	batchSize := 200 // from our implementation
	numFeatures := int(float64(batchSize) * 2.5)

	var manyFeatures []string
	for i := range numFeatures {
		manyFeatures = append(manyFeatures, strconv.Itoa(i))
	}

	sh := s.NewSimhash(manyFeatures, 64, "", nil, nil)

	if sh.Value.Sign() == 0 {
		t.Error("Simhash value should not be zero for many features")
	}

	largeWeightFeatures := make(map[string]int)
	for i, feature := range manyFeatures {
		largeWeightFeatures[feature] = 50 * (i + 1) // large weights
	}

	sh2 := s.NewSimhash(largeWeightFeatures, 64, "", nil, nil)

	if sh2.Value.Sign() == 0 {
		t.Error("Simhash value should not be zero for large weight features")
	}

	if sh.Equal(sh2) {
		t.Error("Different feature weightings should produce different simhashes")
	}
}
