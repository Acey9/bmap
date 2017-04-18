NAME?=onepiece

all:
	go build -o $(NAME) *.go

.PHONY: clean
clean:
	rm -fr $(NAME)
