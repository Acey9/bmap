NAME?=onepiece

all:
	go build -o $(NAME) *.go

release:
	go build -ldflags "-s -w"  -o $(NAME) *.go

.PHONY: clean
clean:
	rm -fr $(NAME)
