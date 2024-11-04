#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define PORT 4444
#define CERT_FILE "server_cert.pem"
#define KEY_FILE "server_key.pem"
#define BUFFER_SIZE 1024
int main() {
    SSL_CTX *ctx;
    SSL *ssl;
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len;
    char buffer[BUFFER_SIZE];

    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    // Create SSL context
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        fprintf(stderr, "Unable to create SSL context\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Load server certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0 ||
        !SSL_CTX_check_private_key(ctx)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Create server socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Unable to create socket");
        return -1;
    }

    // Set up server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    // Bind and listen
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        return -1;
    }
    listen(server_fd, 1);
    printf("Server listening on port %d\n", PORT);

    // Accept client connection
    addr_len = sizeof(client_addr);
    client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &addr_len);
    if (client_fd < 0) {
        perror("Accept failed");
        return -1;
    }
    printf("Client connected.\n");

    // Create SSL connection
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_fd);
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        close(client_fd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(server_fd);
        return -1;
    }
    printf("SSL handshake completed.\n");

    // Read from client
    int len = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (len > 0) {
        buffer[len] = '\0';
        printf("Received message: %s\n", buffer);

        // Send response
        const char *reply = "Hello from TCP server";
        SSL_write(ssl, reply, strlen(reply));
    } else {
        ERR_print_errors_fp(stderr);
    }

    // Cleanup
    SSL_free(ssl);
    close(client_fd);
    close(server_fd);
    SSL_CTX_free(ctx);
    printf("Server connection closed.\n");

    return 0;
}
