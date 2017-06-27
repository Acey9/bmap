package mirai

import (
	"github.com/Acey9/bmap/scanner"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestScan(t *testing.T) {
	target := &scanner.Target{"10.16.20.55:43333"}
	m := Mirai{}
	res, err := m.Scan(target)
	assert.Equal(t, "1\tnil", res.Response)
	assert.NoError(t, err)
}
