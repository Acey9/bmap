package scanner

type Scanner interface {
	Scan(target *Target) (*Response, error)
}

type Target struct {
	Addr string
}

type Response struct {
	Addr     string
	Response string
}
