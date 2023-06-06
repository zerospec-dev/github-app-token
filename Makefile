build: build-x86 build-arm64

build-x86: main.go
	mkdir -p dist
	GOOS=linux GOARCH=amd64 go build -o dist/github-app-token_linux-amd64 main.go

build-arm64: main.go
	mkdir -p dist
	GOOS=linux GOARCH=arm64 go build -o dist/github-app-token_linux-arm64 main.go
