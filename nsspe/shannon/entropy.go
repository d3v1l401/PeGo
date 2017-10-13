package shannon

import (
	"hash"
	"math"
)

type Shannon struct {
	counts [256]int
	bytes  int
}

// New returns a new hash.Hash computing the MD4 checksum.
func New() hash.Hash {
	s := new(Shannon)
	return s
}

func (s *Shannon) BlockSize() int {
	return 1
}

func (s *Shannon) Size() int {
	return 1
}

func (s *Shannon) Write(b []byte) (int, error) {
	for _, c := range b {
		s.counts[c]++
	}
	s.bytes += len(b)
	return len(b), nil
}

// Sum returns shannon entropy value normalized to 0-255
func (s *Shannon) Sum(b []byte) []byte {
	if b == nil {
		return []byte{byte(s.SumFloat() * 255)}
	}
	return append(b, byte(s.SumFloat()*255))
}

// SumFloat returns value 0-1 value (normal shannon value)
func (s *Shannon) SumFloat() float64 {
	var entropy float64
	for _, count := range s.counts {
		if count > 0 {
			pval := float64(count) / float64(s.bytes)
			pinv := float64(s.bytes) / float64(count)
			entropy += pval * math.Log2(pinv)
		}
	}
	return entropy
}

func (s *Shannon) Reset() {
	*s = Shannon{}
}
