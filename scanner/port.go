package scanner

import (
	"sync"
)

type Set struct {
	m map[uint16]bool
	sync.RWMutex
}

func NewSet() *Set {
	return &Set{
		m: map[uint16]bool{},
	}
}

func (s *Set) Add(item uint16) {
	s.Lock()
	defer s.Unlock()
	s.m[item] = true
}

func (s *Set) Remove(item uint16) {
	s.Lock()
	defer s.Unlock()
	delete(s.m, item)
}

func (s *Set) Has(item uint16) bool {
	s.RLock()
	defer s.RUnlock()
	_, ok := s.m[item]
	return ok
}

func (s *Set) Len() int {
	return len(s.List())
}

func (s *Set) Clear() {
	s.Lock()
	defer s.Unlock()
	s.m = map[uint16]bool{}
}

func (s *Set) IsEmpty() bool {
	if s.Len() == 0 {
		return true
	}
	return false
}

func (s *Set) List() []uint16 {
	s.RLock()
	defer s.RUnlock()
	list := []uint16{}
	for item := range s.m {
		list = append(list, item)
	}
	return list
}
