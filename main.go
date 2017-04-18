package main

import (
	"github.com/bmap/mirai"
	"github.com/bmap/scanner"
)

func main() {
	s := &mirai.Mirai{}
	scanner.Start("mirai", s)
}
