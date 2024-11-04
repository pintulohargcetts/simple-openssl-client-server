#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define PORT 4443
#define BUFFER_SIZE 1024
#define CERT_FILE "server_cert.pem"
#define KEY_FILE "server_key.pem"

int main() {
    SSL_CTX *ctx;
    SSL *ssl;
    int server_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];

    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    // Create DTLS context
    ctx = SSL_CTX_new(DTLS_server_method());
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
        SSL_CTX_free(ctx);
        return -1;
    }

    // Create server socket
    server_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_fd < 0) {
        perror("Unable to create socket");
        SSL_CTX_free(ctx);
        return -1;
    }

    // Set up server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    // Bind the socket
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_fd);
        SSL_CTX_free(ctx);
        return -1;
    }
    printf("DTLS server listening on port %d\n", PORT);

    // Create SSL connection
    ssl = SSL_new(ctx);

    while (1) {
        // Receive message from client
        int len = recvfrom(server_fd, buffer, sizeof(buffer), 0, (struct sockaddr*)&client_addr, &addr_len);
        if (len < 0) {
            perror("Receive failed");
            continue;
        }
        buffer[len] = '\0'; // Null-terminate the received message
        printf("Received message from client: %s\n", buffer);

        // Set the BIO for the SSL
        BIO *bio = BIO_new_dgram(server_fd, BIO_NOCLOSE);
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &client_addr);
        SSL_set_bio(ssl, bio, bio);

        // Accept SSL connection
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            // Send response to client
            const char *reply = "Hello from DTLS server";
            SSL_write(ssl, reply, strlen(reply));
        }

        // Cleanup
        SSL_free(ssl);
        ssl = SSL_new(ctx);
    }

    // Cleanup
    close(server_fd);
    SSL_CTX_free(ctx);
    printf("Server connection closed.\n");

    return 0;
}
