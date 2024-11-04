# Simple openssl client server
### generate your own certificate using following 
```bash 
openssl req -x509 -newkey rsa:2048 -keyout server_key.pem -out server_cert.pem -days 365 -nodes
```
### run to test 
```bash
gcc openssl_tcp_server.c -o openssl_tcp_server -lssl -lcrypto
gcc openssl_tcp_client.c -o openssl_tcp_client -lssl -lcrypto
```
### start server 
```bash
./openssl_tcp_server
```
### start client
```bash
./openssl_tcp_client
```


# Simple dtls server for test 
### run server 
```bash
gcc dtls_server.c -o dtls_server -lssl -lcrypto
```
### test with openssl 
```bash
openssl s_client -dtls -connect 127.0.0.1:4445 
```
