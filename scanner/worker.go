package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/Acey9/bmap/common"
	"github.com/astaxie/beego/logs"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
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

	requestCount  int
	responseCount int
	synscanner    *SynScanner
	active        time.Time
}

func initWorker(name string, s Scanner) error {
	worker = &Worker{
		name:          name,
		scanner:       s,
		whitelist:     make(map[string]int),
		settings:      &settings,
		targetQueue:   make(chan *Target),
		responseQueue: make(chan *Response),
		requestCount:  0,
		responseCount: 0}
	worker.loadWhitelist()

	synscanner, err := NewSynScanner()
	if err != nil {
		return err
	}
	worker.synscanner = synscanner
	worker.active = time.Now()
	return nil
}

func (this *Worker) AddTarget(host string) {
	t := &Target{host}
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

	if this.settings.SynScan {
		logs.Info("%s open", res.Addr)
		return
	}

	out, err := this.scanner.Output(res)
	if err != nil {
		logs.Error(err)
	}
	if out != "" {
		logs.Info("%s %s", this.name, out)
	}
}

func (this *Worker) readSynAck() {
	for {

		data, _, err := this.synscanner.handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			logs.Error("error reading packet: %v", err)
			continue
		}

		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)

		if net := packet.NetworkLayer(); net == nil {
		} else if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer == nil {
			//
		} else if ip, ok := ipLayer.(*layers.IPv4); !ok {
			//
		} else if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer == nil {
			//
		} else if tcp, ok := tcpLayer.(*layers.TCP); !ok {
			//
		} else if tcp.DstPort != 54321 {
			//
		} else if tcp.RST {
			//
		} else if tcp.SYN && tcp.ACK {

			addr := bytes.Buffer{}
			addr.WriteString(ip.SrcIP.String())
			addr.WriteString(":")
			addr.WriteString(strconv.Itoa(int(tcp.SrcPort)))

			if this.settings.SynScan {
				resp := bytes.Buffer{}
				resp.WriteString("open")
				this.AddResponse(&Response{addr.String(), resp.String()})
			} else {
				this.AddTarget(addr.String())
			}

			//logs.Info("%v  port %v open", ip.SrcIP, tcp.SrcPort)
		} else {
			//
		}
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
	ipStr := ipPort[0]
	portStr := ipPort[1]
	_, ok := this.whitelist[ipStr]
	if ok {
		logs.Debug("whitelist hit %s", ipStr)
		return
	}

	if !this.settings.SynScan {
		for {
			if this.requestCount-this.responseCount < this.settings.Concurrency {
				break
			} else {
				time.Sleep(sleep)
			}
		}
	}

	ip := net.ParseIP(ipStr)
	if ip != nil {
		if ip = ip.To4(); ip == nil {
			logs.Error("ip.To4 error.")
			return
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			logs.Error(err)
			return
		}
		this.active = time.Now()
		this.synscanner.syn(ip, layers.TCPPort(port))
	} else {
		this.active = time.Now()
		this.AddTarget(host)
	}
}

func (this *Worker) waittingForEnd() {
	sleep := time.Millisecond * time.Duration(1)
	for {
		if time.Since(this.active) > time.Second*time.Duration(this.settings.Timeout) {
			break
		}
		time.Sleep(sleep)
	}
}

func (this *Worker) Run() error {

	go this.despatch()
	go this.readSynAck()

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
	err := initWorker(name, s)
	if err != nil {
		fmt.Println(err)
		logs.Error(err)
		return
	}
	defer worker.synscanner.close()
	worker.Run()
}
