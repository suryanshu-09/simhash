package tests

import (
	"testing"

	s "github.com/suryanshu-09/simhash/simhash"
)

func TestSimhash(t *testing.T) {
	t.Run("check equals", func(t *testing.T) {
		s1 := s.Simhash{Value: 4390059585430954713, F: 0, Reg: nil, Hash: nil, Log: nil}
		s2 := s.Simhash{Value: 4390059585430954713, F: 0, Reg: nil, Hash: nil, Log: nil}
		if !s1.Equals(s2) {
			t.Errorf("got:%d\nwant%d", s1.Value, s2.Value)
		}
	})

	t.Run("check unequals", func(t *testing.T) {
		s1 := s.Simhash{Value: 4390059585430954713, F: 0, Reg: nil, Hash: nil, Log: nil}
		s2 := s.Simhash{Value: 4390059585435954713, F: 0, Reg: nil, Hash: nil, Log: nil}
		if s1.Equals(s2) {
			t.Errorf("got:%d\nwant%d", s1.Value, s2.Value)
		}
	})

	t.Run("check 0", func(t *testing.T) {
		s1 := s.Simhash{Value: 0, F: 0, Reg: nil, Hash: nil, Log: nil}
		if s1.Value != 0 {
			t.Errorf("got:%d\nwant%d", s1.Value, 0)
		}
	})

	t.Run("check simhash", func(t *testing.T) {
		s1 := s.Simhash{Value: 0, F: 0, Reg: nil, Hash: nil, Log: nil}
		s1.BuildByFeatures(map[string]int{"aaa": 1, "bbb": 1})
		if s1.Value != 57087923692560392 {
			t.Errorf("got:%d\nwant:%d", s1.Value, 57087923692560392)
		}
	})
}
