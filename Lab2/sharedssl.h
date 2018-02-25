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
int init_certs(char *keyfile,char *password);
void show_cert(SSL* ssl);
int std_exit(char *out);
int ssl_exit(char *out);