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

#define CN_SERVER "Bob's Server"
#define EMAIL "ece568bob@ecf.utoronto.ca"
#define CLIENTKEYFILE "alice.pem"
#define CLIENTPASSWORD "password"
#define CA_LIST "568ca.pem"

/* use these strings to tell the marker what is happening */
#define FMT_CONNECT_ERR "ECE568-CLIENT: SSL connect error\n"
#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"
#define FMT_OUTPUT "ECE568-CLIENT: %s %s\n"
#define FMT_CN_MISMATCH "ECE568-CLIENT: Server Common Name doesn't match\n"
#define FMT_EMAIL_MISMATCH "ECE568-CLIENT: Server Email doesn't match\n"
#define FMT_NO_VERIFY "ECE568-CLIENT: Certificate does not verify\n"
#define FMT_INCORRECT_CLOSE "ECE568-CLIENT: Premature close\n"

//same as server function but now checks cert on client side
int check_server_cert(SSL *ssl){

  X509 *check;
  char check_CN[256];
  char check_email[256];
  char check_certificate_issuer[256];
  
  check = SSL_get_peer_certificate(ssl);
  
  if ((check == NULL) || (SSL_get_verify_result(ssl) != X509_V_OK)){
    printf(FMT_NO_VERIFY);
    return -1;
  }
  
  X509_NAME_get_text_by_NID (X509_get_subject_name(check), NID_commonName, check_CN, 256);
  X509_NAME_get_text_by_NID (X509_get_subject_name(check), NID_pkcs9_emailAddress, check_email, 256);  
  X509_NAME_get_text_by_NID (X509_get_issuer_name(check), NID_commonName, check_certificate_issuer, 256);
  
  if (strcmp(check_CN,CN_SERVER)) {
        printf(FMT_CN_MISMATCH);        
        return -1;        
  }
    
  if (strcmp(check_email, EMAIL)) {
        printf(FMT_EMAIL_MISMATCH);
        return -1;
    }
    
  printf(FMT_SERVER_INFO, check_CN, check_email, check_certificate_issuer);
  return 0;
  
}

void read_write_client(SSL *ssl, char * secret){

  char buf[256];
  int secret_length = strlen(secret);
  int length_read;

  //Write the secret to ssl connection
  int err = SSL_write(ssl,secret,secret_length);
  
  switch(SSL_get_error(ssl,err)){
    case SSL_ERROR_NONE:
        if(secret_length!=err)
            printf("Incorrect secret length");
            return;
    case SSL_ERROR_ZERO_RETURN:
    	err=SSL_shutdown(ssl);
    	if(err != 1){
    			printf("SSL Shutdown Borked");
    		}
        printf(FMT_INCORRECT_CLOSE);
        SSL_free(ssl);
        return;    		
    case SSL_ERROR_SYSCALL:
        printf(FMT_INCORRECT_CLOSE);
        SSL_free(ssl);
        return;
    default:
        printf("SSL write failure");
    }
    
    /*Read from the ssl connection */
    while(1){
        err=SSL_read(ssl,buf,256);
        
       	//cases for each error we want
        switch(SSL_get_error(ssl,err)){
            case SSL_ERROR_NONE:
                length_read=err;
                return;
            case SSL_ERROR_ZERO_RETURN:
     			err=SSL_shutdown(ssl);
    			if(err != 1){
    				printf("SSL Shutdown Borked");
    			}
                printf(FMT_INCORRECT_CLOSE);
                SSL_free(ssl);
                return;    			               
            case SSL_ERROR_SYSCALL:
                printf(FMT_INCORRECT_CLOSE);
                SSL_free(ssl);
                return;
            default:
                printf("SSL read failure");
        }
        buf[length_read]='\0';
        printf(FMT_OUTPUT, secret, buf);
    }
}

int main(int argc, char **argv)
{
  int sock, port=PORT;
  char *host=HOST;
  struct hostent *host_entry;
  struct sockaddr_in addr;    
  char *secret = "What's the question?";
  SSL_CTX *ctx; 
  SSL *ssl; 
  BIO *sbio;  

  /*Parse command line arguments*/
  switch(argc){
    case 1: //if 1 arg, which is just ./client then use port 8765
      break;
    case 3: //if 3 args, use hostname entered and portnumber given
      host = argv[1];
      port=atoi(argv[2]);
      if (port<1||port>65535){
    fprintf(stderr,"invalid port number");
    exit(0);
      }
      break;
    default:  //if random number of arguents, then print this and exit
      printf("Usage: %s server port\n", argv[0]);
      exit(0);
  }

  //Context Initializaton: load our own keys
  ctx = init_certs(CLIENTKEYFILE, CLIENTPASSWORD);
  
  //Set CTX options to communicate with servers using SSLv3 or TLSv1 by only removing SSLv2
  
  //set cipher list to SHA1
  SSL_CTX_set_cipher_list(ctx, "SHA1:SSLv3:TLSv1");
  
  //Creates a tcp connection
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
  if((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0)  //creates socket
    perror("Error: Couldn't create socket");
  if(connect(sock,(struct sockaddr *)&addr, sizeof(addr))<0)  //connects
    perror("Error: Couldn't connect to socket");

  ssl = SSL_new(ctx);
  sbio = BIO_new_socket(sock,BIO_NOCLOSE); //read and write socket BIO
  SSL_set_bio(ssl,sbio,sbio);
  
  //Initiate the SSL handshake with a server
    int r = 0;
    if((r = SSL_connect(ssl)) <=0) {
        printf(FMT_CONNECT_ERR);
        ERR_print_errors_fp(stdout);
        SSL_CTX_free(ctx);
        return 1;
    }
    
    //ssl connection worked, check server cert
    if (check_server_cert(ssl) == 0) {
    	//if cert checks out, send message
    	show_cert(ssl);
        read_write_client(ssl, secret);
    }

    SSL_CTX_free(ctx);
    close(sock);
    return 1;
}
