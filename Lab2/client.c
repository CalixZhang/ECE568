#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "sharedssl.h"

#define HOST "localhost"
#define PORT 8765

/* use these strings to tell the marker what is happening */
#define FMT_CONNECT_ERR "ECE568-CLIENT: SSL connect error\n"
#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"
#define FMT_OUTPUT "ECE568-CLIENT: %s %s\n"
#define FMT_CN_MISMATCH "ECE568-CLIENT: Server Common Name doesn't match\n"
#define FMT_EMAIL_MISMATCH "ECE568-CLIENT: Server Email doesn't match\n"
#define FMT_NO_VERIFY "ECE568-CLIENT: Certificate does not verify\n"
#define FMT_INCORRECT_CLOSE "ECE568-CLIENT: Premature close\n"


int main(int argc, char **argv)
{
  int len, sock, port=PORT, err;
  char *host=HOST;
  struct sockaddr_in addr;
  struct hostent *host_entry;
  char buf[256];
  char *secret = "What's the question?";

  BIO *sbio;
  SSL_CTX *ssl_ctx;
  SSL *ssl;
  X509 *server_cert;

  init_ssl();

  ssl_ctx = SSL_CTX_new(SSLv3_client_method());

  // Enable certificate validation
  SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

  // Configure the CA trust store to be used
  if (SSL_CTX_load_verify_locations(ssl_ctx, "568ca.pem", NULL) != 1) {
    fprintf(stderr, "Couldn't load certificate trust store.\n");
    return;
  }

  err = init_certs(ssl_ctx, "alice.pem");
  if(err != 0){
    printf(FMT_NO_VERIFY);    
    return;
  }
  /*Parse command line arguments*/
  switch(argc){
    case 1:
      break;
    case 3:
      host = argv[1];
      port=atoi(argv[2]);
      if (port<1||port>65535){
	fprintf(stderr,"invalid port number");
	exit(0);
      }
      break;
    default:
      printf("Usage: %s server port\n", argv[0]);
      exit(0);
  }
  
  /*get ip address of the host*/
  
  host_entry = gethostbyname(host);
  
  if (!host_entry){
    fprintf(stderr,"Couldn't resolve host");
    exit(0);
  }

  memset(&addr,0,sizeof(addr));
  addr.sin_addr=*(struct in_addr *) host_entry->h_addr_list[0];
  addr.sin_family=AF_INET;
  addr.sin_port=htons(port);
  
  printf("Connecting to %s(%s):%d\n", host, inet_ntoa(addr.sin_addr),port);
  
  /*open socket*/
  
  if((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0)
    perror("socket");
  if(connect(sock,(struct sockaddr *)&addr, sizeof(addr))<0)
    perror("connect");
  
  // Create the SSL connection
  sbio = BIO_new_ssl_connect(ssl_ctx);
  BIO_get_ssl(sbio, &ssl); 
  if(!ssl) {
    fprintf(stderr, "Can't locate SSL pointer\n");
    return;
  }

  // Recover the server's certificate
  show_cert(ssl);
  server_cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
  if (server_cert == NULL) {
    printf("No server cert\n");
    // The handshake was successful although the server did not provide a certificate
    // Most likely using an insecure anonymous cipher suite... get out!
  }

  send(sock, secret, strlen(secret),0);

  len = recv(sock, &buf, 255, 0);
  buf[len]='\0';
  
  /* this is how you output something for the marker to pick up */
  printf(FMT_OUTPUT, secret, buf);
  
  close(sock);
  return 1;
}