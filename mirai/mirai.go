package mirai

import (
	"fmt"
	"github.com/bmap/scanner"
	"net"
	"time"
)

const UNKNOWN int = 0
const MIRAI int = 1
const CONNERR int = 2
const READERR int = 3
const ACKLEN = 2
const CONNTIMEOUT = 5
const WRITETIMEOUT = 3
const READTIMEOUT = 5

const LOGINMSG string = "\x00\x00\x00\x01\x0a\x74\x65\x6c\x6e\x65\x74\x2e\x78\x38\x36"
const HEARTBEAT = "\x13\x7f"

type Bot struct {
	conn      net.Conn
	heatebeat string
	loginMsg  string
}

type Mirai struct {
}

func (mirai *Mirai) Output(response *scanner.Response) (string, error) {
	out := fmt.Sprintf("%s\t%s", response.Addr, response.Response)
	return out, nil
}

func (mirai *Mirai) Scan(target *scanner.Target) (*scanner.Response, error) {
	conn, err := net.DialTimeout("tcp", target.Addr, time.Second*CONNTIMEOUT)
	if err != nil {
		msg := fmt.Sprintf("%d\t%s", CONNERR, err)
		res := &scanner.Response{target.Addr, msg}
		return res, nil
	}
	defer conn.Close()

	bot := NewBot(conn, HEARTBEAT, LOGINMSG)

	var msg string
	for i := 0; i < 2; i++ {
		ck, err := bot.Login()
		if ck {
			msg = fmt.Sprintf("%d\t%s", MIRAI, "nil")
			break
		} else {
			msg = fmt.Sprintf("%d\t%s", UNKNOWN, err)
		}
	}

	res := &scanner.Response{target.Addr, msg}
	return res, nil
}

func NewBot(conn net.Conn, heatebeat string, loginMsg string) *Bot {
	return &Bot{conn, heatebeat, loginMsg}
}

func (bot *Bot) Login() (bool, error) {
	loginMsg := []byte(bot.loginMsg)

	sleep := time.Millisecond * time.Duration(5)

	bot.conn.SetWriteDeadline(time.Now().Add(time.Second * WRITETIMEOUT))
	_, err := bot.conn.Write(loginMsg[:4])
	if err != nil {
		return false, err
	}
	time.Sleep(sleep)

	bot.conn.SetWriteDeadline(time.Now().Add(time.Second * WRITETIMEOUT))
	_, err = bot.conn.Write(loginMsg[4:15])
	if err != nil {
		return false, err
	}
	heartbeat := []byte(bot.heatebeat) //TODO random
	time.Sleep(sleep)

	bot.conn.SetWriteDeadline(time.Now().Add(time.Second * WRITETIMEOUT))
	_, err = bot.conn.Write(heartbeat)
	if err != nil {
		return false, err
	}

	ackBuf := make([]byte, 3)

	bot.conn.SetReadDeadline(time.Now().Add(time.Second * READTIMEOUT))
	n, err := bot.conn.Read(ackBuf)
	if err != nil {
		return false, err
	}

	res := bot.confirm(n, ackBuf, heartbeat)
	if res != MIRAI {
		return false, nil
	}
	return true, nil
}

func (bot *Bot) confirm(n int, ackBuf, heartbeat []byte) int {
	if n == ACKLEN && ackBuf[0] == heartbeat[0] && ackBuf[1] == heartbeat[1] {

		hb := []byte("\x13\xff")
		bcount := 0
		for i := 0; i < 3; i++ {
			buf := make([]byte, 3)
			bot.conn.SetWriteDeadline(time.Now().Add(time.Second * WRITETIMEOUT))
			bot.conn.Write(hb)

			bot.conn.SetReadDeadline(time.Now().Add(time.Second * READTIMEOUT))
			ln, err := bot.conn.Read(buf)
			if err != nil {
				continue
			}

			if ln == ACKLEN && buf[0] == hb[0] && buf[1] == hb[1] {
				bcount++
			}
			time.Sleep(time.Millisecond * 1000)
		}
		if bcount == 0 {
			return UNKNOWN
		} else {
			return MIRAI
		}
	}
	return UNKNOWN
}
