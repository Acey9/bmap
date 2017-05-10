package scanner

import (
	//"fmt"
	"sync"
	"time"
)

const SessionExpired = 180

type Session struct {
	tab      map[string]time.Time
	cntMutex *sync.RWMutex
}

func NewSesson() *Session {
	s := &Session{tab: make(map[string]time.Time),
		cntMutex: &sync.RWMutex{}}
	go s.clean()
	return s
}

func (s *Session) AddSession(sid string) {
	//fmt.Println("AddSession:", sid)
	s.cntMutex.Lock()
	defer s.cntMutex.Unlock()
	s.tab[sid] = time.Now()
}

func (s *Session) QuerySession(sid string) bool {
	s.cntMutex.Lock()
	defer s.cntMutex.Unlock()
	_, ok := s.tab[sid]
	if ok {
		return true
	}
	return false
}

func (s *Session) DeleteSession(sid string) {
	//fmt.Println("DeleteSession:", sid)
	s.cntMutex.Lock()
	defer s.cntMutex.Unlock()
	delete(s.tab, sid)
}

func (s *Session) clean() {
	sleep := time.Millisecond * time.Duration(1000)
	for {
		for k, v := range s.tab {
			if time.Since(v) > time.Second*SessionExpired {
				s.DeleteSession(k)
			}
		}
		time.Sleep(sleep)
	}
}