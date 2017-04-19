package scanner

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/Acey9/bmap/common"
	"github.com/astaxie/beego/logs"
	"net"
	"os"
	"runtime"
	"strings"
	"time"
)

var settings Settings

var worker *Worker

type Settings struct {
	Concurrency   int
	Gomaxprocs    int
	ScanFile      string
	WhitelistFile string
	Args          []string
}

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
			out, err := this.scanner.Output(res)
			if err == nil {
				logs.Info("%s %s", this.name, out)
			} else {
				logs.Error(err)
			}
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
		ip := net.ParseIP(line)
		if ip != nil {
			this.whitelist[line] = 1
			continue
		}
		ips, err := common.CIDR2IP(line)
		if err != nil {
			logs.Error("Whitelist %s", err)
			continue
		}
		for _, ipStr := range ips {
			this.whitelist[ipStr] = 1
		}
	}
	return nil
}

func (this *Worker) scanFromFile() {
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
		this.scanFromFile()
	} else {
		logs.Warn("No target")
	}

	this.waittingEnd()

	return nil
}

func optParse() {
	flag.StringVar(&settings.ScanFile, "iL", "", "Input from list of hosts/networks")
	flag.StringVar(&settings.WhitelistFile, "w", "", "Input whitelist from list of hosts/networks")

	flag.IntVar(&settings.Concurrency, "c", 10, "concurrency")
	flag.IntVar(&settings.Gomaxprocs, "p", 0, "go max procs")

	flag.Parse()
	if settings.Gomaxprocs == 0 {
		settings.Gomaxprocs = runtime.NumCPU()
	}
	settings.Args = flag.Args()
}

func init() {
	optParse()
	runtime.GOMAXPROCS(settings.Gomaxprocs)
}

func Start(name string, s Scanner) {
	initWorker(name, s)
	worker.Run()
}
