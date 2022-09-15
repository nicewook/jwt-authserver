cert:
	openssl genrsa -out server.key 2048
	openssl req -new -x509 -sha256 -key server.key -out server.crt -days 365

run :
	cd cmd/authserver
	nodemon --exec go run ./cmd/authserver/ --signal SIGTERM