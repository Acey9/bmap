package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/Acey9/bmap/common"
	"github.com/astaxie/beego/logs"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var worker *Worker

type Worker struct {
	name      string
	scanner   Scanner
	whitelist map[string]int
	settings  *Settings

	targetQueue   chan *Target
	responseQueue chan *Response

	requestCount  int
	responseCount int
}

func initWorker(name string, s Scanner) {
	worker = &Worker{
		name,
		s,
		make(map[string]int),
		&settings,
		make(chan *Target),
		make(chan *Response),
		0,
		0}
	worker.loadWhitelist()
}

func (this *Worker) AddTarget(t *Target) {
	this.targetQueue <- t
}

func (this *Worker) AddResponse(r *Response) {
	this.responseQueue <- r
}

func (this *Worker) goScan(target *Target) {
	defer func() {
		if err := recover(); err != nil {
			msg := fmt.Sprintf("%s", err)
			res := &Response{target.Addr, msg}
			this.AddResponse(res)
		}
	}()

	res, err := this.scanner.Scan(target)
	if err != nil {
		msg := fmt.Sprintf("%s", err)
		res := &Response{target.Addr, msg}
		this.AddResponse(res)
		return
	}
	this.AddResponse(res)
}

func (this *Worker) output(res *Response) {

	defer func() {
		if err := recover(); err != nil {
			logs.Error(err)
		}
	}()

	out, err := this.scanner.Output(res)
	if err != nil {
		logs.Error(err)
	}
	if out != "" {
		logs.Info("%s %s", this.name, out)
	}
}

func (this *Worker) despatch() {
	for {
		select {
		case t := <-this.targetQueue:
			this.requestCount++
			//logs.Debug("-> %s", t.Addr)
			go this.goScan(t)
			break
		case res := <-this.responseQueue:
			this.responseCount++
			/*if this.responseCount%100000 == 0 {
				logs.Debug("Progress %d:%d", this.responseCount, this.requestCount)
			}*/
			this.output(res)
			break
		}
	}
}

func (this *Worker) loadWhitelist() error {
	if this.settings.WhitelistFile == "" {
		logs.Warn("Whitelist nonexist.")
		return nil
	}
	fd, err := os.Open(this.settings.WhitelistFile)
	if err != nil {
		logs.Error("%s", err)
		return err
	}
	defer fd.Close()

	wl := bufio.NewScanner(fd)
	for wl.Scan() {
		text := wl.Text()
		line := strings.TrimSpace(text)
		i := strings.IndexByte(line, '/')
		if i < 0 {
			this.whitelist[line] = 1
			continue
		} else {
			ips, err := common.CIDR2IP(line)
			if err != nil {
				logs.Error("Whitelist %s", err)
				continue
			}
			for _, ipStr := range ips {
				this.whitelist[ipStr] = 1
			}
		}
	}
	return nil
}

func (this *Worker) pushHost(ip string) {
	for _, port := range this.settings.Ports {
		t := bytes.Buffer{}
		t.WriteString(ip)
		t.WriteString(":")
		t.WriteString(strconv.Itoa(int(port)))
		this.pushTarget(t.String())
	}
}

func (this *Worker) pushTarget(addr string) {
	sleep := time.Millisecond * time.Duration(1)
	host := strings.TrimSpace(addr)

	ipPort := strings.Split(host, ":")
	ip := ipPort[0]
	_, ok := this.whitelist[ip]
	if ok {
		logs.Debug("whitelist hit %s", ip)
		return
	}

	for {
		if this.requestCount-this.responseCount < this.settings.Concurrency {
			break
		} else {
			time.Sleep(sleep)
		}
	}
	target := &Target{host}
	this.AddTarget(target)
}

func (this *Worker) waittingForEnd() {
	time.Sleep(time.Millisecond * time.Duration(5000))
	sleep := time.Millisecond * time.Duration(1)
	for {
		if this.requestCount == this.responseCount {
			break
		}
		time.Sleep(sleep)
	}
}

func (this *Worker) Run() error {

	go worker.despatch()

	if this.settings.ScanFile != "" {
		listParse()
	} else {
		inputParse()
	}

	this.waittingForEnd()

	return nil
}

func init() {
	optParse()
	runtime.GOMAXPROCS(settings.Gomaxprocs)
}

func Start(name string, s Scanner) {
	initWorker(name, s)
	worker.Run()
}
