package scanner

import (
	"errors"
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

func splitComma(s string) []string {
	var buf []string
	i := strings.IndexByte(s, ',')
	if i < 0 {
		buf = append(buf, s)
	} else {
		for _, ss := range strings.Split(s, ",") {
			buf = append(buf, ss)
		}
	}
	return buf
}

func portRange(s string) (min, max int, err error) {
	i := strings.IndexByte(s, '-')
	if i < 0 {
		min, err := strconv.Atoi(s)
		if err != nil {
			return min, max, err
		}
		max = min
		return min, max, err
	} else {
		tmp := strings.Split(s, "-")
		if len(tmp) != 2 {
			return min, max, errors.New("range error")
		}
		min, err := strconv.Atoi(tmp[0])
		if err != nil {
			return min, max, err
		}

		max, err := strconv.Atoi(tmp[1])
		if err != nil {
			return min, max, err
		}

		if min < max {
			return min, max, nil
		} else {
			return max, min, nil
		}
	}
	return min, max, err
}

func portsParse(portStr string) (ports []int, err error) {

	if portStr == "" {
		return ports, err
	}

	list := splitComma(portStr)

	portSet := NewSet()
	for _, s := range list {
		min, max, err := portRange(s)
		if err != nil {
			return ports, err
		}
		if max > 65535 {
			return ports, errors.New("The port maximum value is 65535.")
		}
		for i := min; i <= max; i++ {
			portSet.Add(i)
		}
	}
	return portSet.List(), nil
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

	ports, err := portsParse(*s)
	if err != nil {
		flag.Usage()
		fmt.Println(err)
		os.Exit(1)
	}
	settings.Ports = ports

	settings.Args = flag.Args()

	if settings.ScanFile == "" && (len(settings.Args) < 1 || (len(settings.Args) > 0 && len(settings.Ports) < 1)) {
		flag.Usage()
		fmt.Println("Option error.")
		os.Exit(1)
	}

	if settings.Gomaxprocs == 0 {
		settings.Gomaxprocs = runtime.NumCPU()
	}
}
