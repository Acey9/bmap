package scanner

import (
	//"fmt"
	"time"
)

const SessionExpired = 300

type Session struct {
	tab map[string]time.Time
}

func NewSesson() *Session {
	s := &Session{tab: make(map[string]time.Time)}
	go s.clean()
	return s
}

func (s *Session) AddSession(sid string) {
	//fmt.Println("AddSession:", sid)
	s.tab[sid] = time.Now()
}

func (s *Session) QuerySession(sid string) bool {
	_, ok := s.tab[sid]
	if ok {
		return true
	}
	return false
}

func (s *Session) DeleteSession(sid string) {
	//fmt.Println("DeleteSession:", sid)
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
