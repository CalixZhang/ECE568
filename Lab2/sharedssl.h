#include <openssl/err.h>
#include <openssl/ssl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void init_ssl(void);
int init_certs(SSL_CTX *ssl_ctx, char *cert_name);
void show_cert(SSL* ssl);