package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/Acey9/bmap/common"
	"github.com/astaxie/beego/logs"
	"net"
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
	inputQueur    chan string

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
		make(chan string),
		0,
		0}
	worker.ReadWhitelist()
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
	if err == nil {
		logs.Info("%s %s", this.name, out)
	} else {
		logs.Error(err)
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

func (this *Worker) ReadWhitelist() error {
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

func (this *Worker) parseList() {
	targetFile, err := os.Open(this.settings.ScanFile)
	if err != nil {
		logs.Error("%s", err)
		return
	}
	defer targetFile.Close()

	fielScanner := bufio.NewScanner(targetFile)
	for fielScanner.Scan() {
		addr := fielScanner.Text()
		this.pushTarget(addr)
	}
}

func (this *Worker) parseInput() {
	var inputs []string

	args := this.settings.Args[0]
	i := strings.IndexByte(args, ',')
	if i < 0 {
		inputs = append(inputs, args)
	} else {
		inputs = strings.Split(args, ",")
	}

	for _, input := range inputs {
		if input == "" {
			continue
		}

		i := strings.IndexByte(input, '/')
		if i < 0 {
			this.pushIP(input, this.settings.Ports)
		} else {
			ip, ipnet, err := net.ParseCIDR(input)
			if err != nil {
				logs.Error("input %s", err)
				continue
			}

			for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); common.Inc(ip) {
				this.pushIP(ip.String(), this.settings.Ports)
			}
		}

	}

}

func (this *Worker) pushIP(ip string, ports []int) {
	for _, port := range ports {
		t := bytes.Buffer{}
		t.WriteString(ip)
		t.WriteString(":")
		t.WriteString(strconv.Itoa(port))
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

func (this *Worker) waittingEnd() {
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
		this.parseList()
	} else {
		this.parseInput()
	}

	this.waittingEnd()

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
