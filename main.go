package main

import (
	"mirai"
	"scanner"
)

func main() {
	s := &mirai.Mirai{}
	scanner.Start("mirai", s)
}
