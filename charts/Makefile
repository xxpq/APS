all: clean bindata.go

install: 
	go install github.com/go-bindata/go-bindata/...

bindata.go: static/index.html static/main.js
	~/go/bin/go-bindata -pkg='bindata' -o bindata/bindata.go static/

clean:
	rm -f bindata/bindata.go
	rm -f example
