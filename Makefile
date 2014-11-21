totp: totp.go
	go build totp.go

install: totp
	cp totp /usr/local/bin/totp
