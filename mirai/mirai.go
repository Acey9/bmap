package mirai

import (
	"github.com/bmap/scanner"
)

type Mirai struct {
}

func (this *Mirai) Scan(target *scanner.Target) (*scanner.Response, error) {
	res := &scanner.Response{target.Addr, "res"}
	return res, nil
}
