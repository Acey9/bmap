package main

import (
	"github.com/Acey9/bmap/mirai"
	"github.com/Acey9/bmap/scanner"
)

func main() {
	s := &mirai.Mirai{}
	scanner.Start("mirai", s)
}
