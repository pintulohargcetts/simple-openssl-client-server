# simple-openssl-client-server
simple-openssl-client-server

# generate your own certificate using following 
openssl req -x509 -newkey rsa:2048 -keyout server_key.pem -out server_cert.pem -days 365 -nodes

# run to test 
gcc openssl_tcp_server.c -o openssl_tcp_server -lssl -lcrypto
gcc openssl_tcp_client.c -o openssl_tcp_client -lssl -lcrypto

# start server 
./openssl_tcp_server
# start client
./openssl_tcp_client
