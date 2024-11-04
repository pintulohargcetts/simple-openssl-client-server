#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define PORT 4444
#define BUFFER_SIZE 1024
#define CA_CERT_FILE "server_cert.pem"  // For verification, but can be ignored for testing

int main() {
    SSL_CTX *ctx;
    SSL *ssl;
    int sockfd;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE] = "Hello from TCP client";

    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    // Create SSL context
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        fprintf(stderr, "Unable to create SSL context\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Disable certificate verification for testing
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Unable to create socket");
        return -1;
    }

    // Set up server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);

    // Connect to server
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connect failed");
        close(sockfd);
        return -1;
    }

    // Create SSL connection
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sockfd);
        SSL_CTX_free(ctx);
        return -1;
    }
    printf("SSL handshake completed.\n");

    // Send message to server
    printf("Sending message: %s\n", buffer);
    SSL_write(ssl, buffer, strlen(buffer));

    // Receive response from server
    int len = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (len > 0) {
        buffer[len] = '\0';
        printf("Received response from server: %s\n", buffer);
    } else {
        ERR_print_errors_fp(stderr);
    }

    // Cleanup
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    printf("Client connection closed.\n");

    return 0;
}
