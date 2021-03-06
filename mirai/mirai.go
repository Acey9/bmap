package mirai

import (
	"fmt"
	"github.com/Acey9/bmap/scanner"
	"net"
	"time"
)

const UNKNOWN int = 0
const MIRAI int = 1
const CONNERR int = 2
const NETERROR int = 3
const ACKLEN = 2
const CONNTIMEOUT = 5
const WRITETIMEOUT = 3
const READTIMEOUT = 5

const LOGINMSG string = "\x00\x00\x00\x01\x00"
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
		if err != nil {
			msg = fmt.Sprintf("%d\t%s", ck, "nil")
			continue
		}
		if ck == MIRAI {
			msg = fmt.Sprintf("%d\t%s", ck, "nil")
			break
		} else {
			msg = fmt.Sprintf("%d\t%s", ck, "nil")
		}
	}

	res := &scanner.Response{target.Addr, msg}
	return res, nil
}

func NewBot(conn net.Conn, heatebeat string, loginMsg string) *Bot {
	return &Bot{conn, heatebeat, loginMsg}
}

func (bot *Bot) Login() (int, error) {
	loginMsg := []byte(bot.loginMsg)

	sleep := time.Millisecond * time.Duration(5)

	bot.conn.SetWriteDeadline(time.Now().Add(time.Second * WRITETIMEOUT))
	_, err := bot.conn.Write(loginMsg[:4])
	if err != nil {
		return NETERROR, err
	}
	time.Sleep(sleep)

	bot.conn.SetWriteDeadline(time.Now().Add(time.Second * WRITETIMEOUT))
	_, err = bot.conn.Write(loginMsg[4:5])
	if err != nil {
		return NETERROR, err
	}
	heartbeat := []byte(bot.heatebeat) //TODO random
	time.Sleep(sleep)

	bot.conn.SetWriteDeadline(time.Now().Add(time.Second * WRITETIMEOUT))
	_, err = bot.conn.Write(heartbeat)
	if err != nil {
		return NETERROR, err
	}

	ackBuf := make([]byte, 4)

	bot.conn.SetReadDeadline(time.Now().Add(time.Second * READTIMEOUT))
	n, err := bot.conn.Read(ackBuf)
	if err != nil {
		return NETERROR, err
	}

	res := bot.confirm(n, ackBuf, heartbeat)
	return res, nil
}

func (bot *Bot) confirm(n int, ackBuf, heartbeat []byte) int {
	if n == ACKLEN && ackBuf[0] == heartbeat[0] && ackBuf[1] == heartbeat[1] {

		hb := []byte("\x13\xff\x6b\x63")
		bcount := 0
		for i := 0; i < 2; i++ {
			buf := make([]byte, 4)
			bot.conn.SetWriteDeadline(time.Now().Add(time.Second * WRITETIMEOUT))
			if i == 0 {
				bot.conn.Write(hb[0:2])
			} else {
				bot.conn.Write(hb[2:])
			}

			bot.conn.SetReadDeadline(time.Now().Add(time.Second * READTIMEOUT))
			ln, err := bot.conn.Read(buf)
			if err != nil {
				continue
			}

			if ln != ACKLEN {
				return UNKNOWN
			}
			if ln == ACKLEN && ((buf[0] == hb[0] && buf[1] == hb[1]) || (buf[0] == hb[2] && buf[1] == hb[3])) {
				bcount++
			}
			time.Sleep(time.Millisecond * 1000)
		}
		if bcount == 2 {
			return MIRAI
		} else {
			return UNKNOWN
		}
	}
	return UNKNOWN
}
