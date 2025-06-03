package tests

import (
	"crypto/md5"
	"crypto/sha256"
	"math/big"
	"strconv"
	"testing"

	s "github.com/suryanshu-09/simhash/simhash"
)

func TestSimhash(t *testing.T) {
	t.Run("test int value", func(t *testing.T) {
		t.Run("normal values", func(t *testing.T) {
			tests := []struct {
				input    int64
				expected int64
			}{
				{0, 0},
				{4390059585430954713, 4390059585430954713},
			}

			for _, test := range tests {
				sh := s.NewSimhash(test.input)
				if sh.Value.Int64() != test.expected {
					t.Errorf("Expected %d, got %d", test.expected, sh.Value.Int64())
				}
			}
		})
		t.Run("large num", func(t *testing.T) {
			largeNum := new(big.Int)
			largeNum.SetString("9223372036854775808", 10)
			sh := s.NewSimhash(largeNum)
			if sh.Value.Cmp(largeNum) != 0 {
				t.Errorf("Expected %s, got %s", largeNum.String(), sh.Value.String())
			}
		})
	})

	t.Run("test value", func(t *testing.T) {
		features := []string{"aaa", "bbb"}
		sh := s.NewSimhash(features)

		if sh.Value.Sign() == 0 {
			t.Error("Simhash value should not be zero for non-empty features")
		}

		sh2 := s.NewSimhash(features)

		if sh.Value.Cmp(sh2.Value) != 0 {
			t.Error("Same input should produce same simhash value")
		}
	})

	t.Run("testing distance", func(t *testing.T) {
		sh := s.NewSimhash("How are you? I AM fine. Thanks. And you?")

		sh2 := s.NewSimhash("How old are you ? :-) i am fine. Thanks. And you?")

		distance := sh.Distance(sh2)
		if distance == 0 {
			t.Error("Distance should be greater than 0 for different texts")
		}

		sh3 := s.NewSimhash(sh2)

		if sh2.Distance(sh3) != 0 {
			t.Error("Distance should be 0 for identical simhashes")
		}

		sh4 := s.NewSimhash("1")

		sh5 := s.NewSimhash("2")

		if sh4.Distance(sh5) == 0 {
			t.Error("Distance should not be 0 for different strings")
		}
	})

	t.Run("testing chinese", func(t *testing.T) {
		sh1 := s.NewSimhash("你好　世界！　　呼噜。")

		sh2 := s.NewSimhash("你好，世界　呼噜")

		sh4 := s.NewSimhash("How are you? I Am fine. ablar ablar xyz blar blar blar blar blar blar blar Thanks.")

		sh5 := s.NewSimhash("How are you i am fine.ablar ablar xyz blar blar blar blar blar blar blar than")

		sh6 := s.NewSimhash("How are you i am fine.ablar ablar xyz blar blar blar blar blar blar blar thank")

		chineseDistance := sh1.Distance(sh2)
		t.Logf("Chinese distance: %d", chineseDistance)

		if sh4.Distance(sh6) >= 10 {
			t.Error("Distance between similar English texts should be small")
		}

		if sh5.Distance(sh6) >= 10 {
			t.Error("Distance between similar English texts should be small")
		}
	})

	t.Run("test short", func(t *testing.T) {
		texts := []string{"aa", "aaa", "aaaa", "aaaab", "aaaaabb", "aaaaabbb"}
		var simhashes []*big.Int

		for _, text := range texts {
			sh := s.NewSimhash(text)
			simhashes = append(simhashes, new(big.Int).Set(sh.Value))
		}

		for i, sh1 := range simhashes {
			for j, sh2 := range simhashes {
				if i != j && sh1.Cmp(sh2) == 0 {
					t.Errorf("Simhashes for '%s' and '%s' should be different", texts[i], texts[j])
				}
			}
		}
	})

	t.Run("test equality comparison", func(t *testing.T) {
		a := s.NewSimhash("My name is John")

		b := s.NewSimhash("My name is John")

		c := s.NewSimhash("My name actually is Jane")

		if !a.Equal(b) {
			t.Error("A should equal B")
		}

		if a.Equal(c) {
			t.Error("A should not equal C")
		}
	})

	t.Run("test custom hashfunc", func(t *testing.T) {
		intHashFunc := func(x []byte) []byte {
			hash := md5.Sum(x)
			hashInt := new(big.Int).SetBytes(hash[:])
			return hashInt.Bytes()
		}

		shaHashFunc := func(x []byte) []byte {
			hash := sha256.Sum256(x)
			return hash[:]
		}

		a := s.NewSimhash("My name is John")

		b := s.NewSimhash("My name is John", s.WithHashFunc(intHashFunc))

		c := s.NewSimhash("My name is John", s.WithHashFunc(shaHashFunc))

		t.Logf("Default hash: %x", a.Value)
		t.Logf("Int hash: %x", b.Value)
		t.Logf("SHA hash: %x", c.Value)

		if a.Equal(c) {
			t.Error("Different hash functions should produce different results")
		}
	})

	t.Run("test large inputs", func(t *testing.T) {
		batchSize := 200
		numFeatures := int(float64(batchSize) * 2.5)

		var manyFeatures []string
		for i := range numFeatures {
			manyFeatures = append(manyFeatures, strconv.Itoa(i))
		}

		sh := s.NewSimhash(manyFeatures)

		if sh.Value.Sign() == 0 {
			t.Error("Simhash value should not be zero for many features")
		}

		largeWeightFeatures := make(map[string]int)
		for i, feature := range manyFeatures {
			largeWeightFeatures[feature] = 50 * (i + 1)
		}

		sh2 := s.NewSimhash(largeWeightFeatures)

		if sh2.Value.Sign() == 0 {
			t.Error("Simhash value should not be zero for large weight features")
		}

		if sh.Equal(sh2) {
			t.Error("Different feature weightings should produce different simhashes")
		}
	})
}

func TestSimhashIndex(t *testing.T) {
	data := []string{
		"How are you? I Am fine. blar blar blar blar blar Thanks.",
		"How are you i am fine. blar blar blar blar blar than",
		"This is simhash test.",
		"How are you i am fine. blar blar blar blar blar thank1",
	}

	objs := make([]s.Object, 0, len(data))
	for i, txt := range data {
		objs = append(objs, s.Object{
			ObjectId: strconv.Itoa(i + 1),
			S:        s.NewSimhash(txt),
		})
	}

	index := s.NewSimhashIndex(objs, s.SimhashIndexWithK(10))

	t.Run("test get near duplicates", func(t *testing.T) {
		s1 := s.NewSimhash("How are you i am fine.ablar ablar xyz blar blar blar blar blar blar blar thank")

		t.Run("test duplicates", func(t *testing.T) {
			dups := index.GetNearDups(s1)
			if len(dups) != 3 {
				t.Errorf("Expected 3 duplicates, got %d: %v", len(dups), dups)
			}
		})

		t.Run("test delete duplicate", func(t *testing.T) {
			index.Delete(s.Object{ObjectId: "1", S: s.NewSimhash(data[0])})
			dups := index.GetNearDups(s1)
			if len(dups) != 2 {
				t.Errorf("After deleting ID=1, expected 2 duplicates, got %d: %v", len(dups), dups)
			}
		})

		t.Run("test delete again", func(t *testing.T) {
			index.Delete(s.Object{ObjectId: "1", S: s.NewSimhash(data[0])})
			dups := index.GetNearDups(s1)
			if len(dups) != 2 {
				t.Errorf("After double delete, expected 2 duplicates, got %d: %v", len(dups), dups)
			}
		})

		t.Run("test add again", func(t *testing.T) {
			index.Add(s.Object{ObjectId: "1", S: s.NewSimhash(data[0])})
			dups := index.GetNearDups(s1)
			if len(dups) != 3 {
				t.Errorf("After adding back ID=1, expected 3 duplicates, got %d: %v", len(dups), dups)
			}
		})

		t.Run("test add again", func(t *testing.T) {
			index.Add(s.Object{ObjectId: "1", S: s.NewSimhash(data[0])})
			dups := index.GetNearDups(s1)
			if len(dups) != 3 {
				t.Errorf("After duplicate add, expected 3 duplicates, got %d: %v", len(dups), dups)
			}
		})
	})
}
