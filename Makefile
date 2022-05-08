.PHONY: build
build: ndp-proxy

.PHONY: run
run: ndp-proxy
	sudo ./ndp-proxy

ndp-proxy: FORCE
	go build -o ndp-proxy main.go

FORCE:
