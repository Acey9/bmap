package scanner

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

var settings Settings

type Settings struct {
	Concurrency   int
	Gomaxprocs    int
	ScanFile      string
	WhitelistFile string
	Args          []string
	Ports         []int
}

func ParsePorts(portStr string) (ports []int, err error) {

	if portStr == "" {
		return ports, err
	}

	i := strings.IndexByte(portStr, ',')
	if i < 0 {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return ports, err
		}
		ports = append(ports, port)
	} else {
		for _, p := range strings.Split(portStr, ",") {
			port, err := strconv.Atoi(p)
			if err != nil {
				return ports, err
			}
			ports = append(ports, port)
		}
	}
	return ports, nil
}

func optParse() {

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s -c 10 -p 23,2323 127.0.0.1,10.1.1.1/24\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.StringVar(&settings.ScanFile, "iL", "", "Input from list of hosts/networks")
	flag.StringVar(&settings.WhitelistFile, "w", "", "Input whitelist from list of hosts/networks")

	flag.IntVar(&settings.Concurrency, "c", 10, "Concurrency")
	flag.IntVar(&settings.Gomaxprocs, "g", 0, "Go max procs")

	s := flag.String("p", "", "Ports")

	flag.Parse()

	ports, err := ParsePorts(*s)
	if err == nil {
		settings.Ports = ports
	}

	settings.Args = flag.Args()

	if settings.ScanFile == "" && (len(settings.Args) < 1 || (len(settings.Args) > 0 && len(settings.Ports) < 1)) {
		flag.Usage()
		os.Exit(1)
	}

	if settings.Gomaxprocs == 0 {
		settings.Gomaxprocs = runtime.NumCPU()
	}
}
