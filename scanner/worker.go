package scanner

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/astaxie/beego/logs"
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
}

type Worker struct {
	scanner   Scanner
	whitelist map[string]int
	settings  *Settings

	targetQueue   chan *Target
	responseQueue chan *Response

	targetCount   int
	responseCount int
}

func initWorker(s Scanner) {
	worker = &Worker{
		s,
		make(map[string]int),
		&settings,
		make(chan *Target),
		make(chan *Response),
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

func (this *Worker) worker() {
	for {
		select {
		case t := <-this.targetQueue:
			this.targetCount++
			logs.Debug("-> %s", t.Addr)
			go this.goScan(t)
			break
		case res := <-this.responseQueue:
			this.responseCount++
			logs.Debug("<- %s", res.Addr)
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
		this.whitelist[line] = 1
	}
	return nil
}

func (this *Worker) Run() error {
	targetFile, err := os.Open(this.settings.ScanFile)
	if err != nil {
		logs.Error("%s", err)
		return err
	}
	defer targetFile.Close()

	fielScanner := bufio.NewScanner(targetFile)
	for fielScanner.Scan() {
		text := fielScanner.Text()
		addr := strings.TrimSpace(text)

		ipPort := strings.Split(addr, ":")
		ip := ipPort[0]
		_, ok := this.whitelist[ip]
		if ok {
			logs.Debug("whitelist hit %s", ip)
			continue
		}

		for {
			if this.targetCount-this.responseCount < this.settings.Concurrency {
				break
			} else {
				sleep := time.Millisecond * time.Duration(1)
				time.Sleep(sleep)
			}
		}
		target := &Target{addr}
		this.AddTarget(target)
	}

	//waitMillisecond := 1 * 60 * 1000
	for {
		//if this.targetCount == this.responseCount || waitMillisecond < 0 {
		if this.targetCount == this.responseCount {
			break
		}
		sleep := time.Millisecond * time.Duration(1)
		time.Sleep(sleep)
		//waitMillisecond--
	}
	return nil
}

func optParse() {
	flag.StringVar(&settings.ScanFile, "t", "./target", "Look for scan target in this directory")
	flag.StringVar(&settings.WhitelistFile, "w", "", "Look for whitelist in this directory")

	concurrency := flag.Int("c", 10, "concurrency")
	gomaxprocs := flag.Int("p", 0, "go max procs")

	flag.Parse()

	settings.Concurrency = *concurrency
	if *gomaxprocs == 0 {
		settings.Gomaxprocs = runtime.NumCPU()
	} else {
		settings.Gomaxprocs = *gomaxprocs
	}
}

func init() {
	optParse()
	runtime.GOMAXPROCS(settings.Gomaxprocs)
}

func Start(name string, s Scanner) {
	initWorker(s)
	go worker.worker()
	worker.Run()
}
