/******************************************************************************/
/***                                                                        ***/
/***                       Preprocessing  Directives                        ***/
/***                                                                        ***/
/******************************************************************************/

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 8765                      // Default Port

/* ADDED: Definitions for our clients */
#define SERVER_KEY_FILE "bob.pem"
#define SERVER_PASSWORD "password"
#define CA_LIST "568ca.pem"

/* use these strings to tell the marker what is happening */
#define FMT_ACCEPT_ERR "ECE568-SERVER: SSL accept error\n"
#define FMT_CLIENT_INFO "ECE568-SERVER: %s %s\n"
#define FMT_OUTPUT "ECE568-SERVER: %s %s\n"
#define FMT_INCOMPLETE_CLOSE "ECE568-SERVER: Incomplete shutdown\n"

/* ADDED: Global Variables */
BIO *bio_err = 0;
static char *pass;

/******************************************************************************/
/***                                                                        ***/
/***                           Helper  Functions                            ***/
/***                                                                        ***/
/******************************************************************************/

/* A simple error and exit routine*/
int err_exit(string)
  char *string;
  {
    fprintf(stderr,"%s\n",string);
    exit(0);
  }

/******************************************************************************/
  
/* Print SSL errors and exit*/
int berr_exit(string)
  char *string;
  {
    BIO_printf(bio_err,"%s\n",string);
    ERR_print_errors(bio_err);
    exit(0);
  }

/******************************************************************************/
  
/*The password code is not thread safe*/
static int password_cb(char *buf,int num,
  int rwflag,void *userdata)
  {
    if(num<strlen(pass)+1)
      return(0);

    strcpy(buf,pass);
    return(strlen(pass));
  }

/******************************************************************************/

SSL_CTX *initialize_ctx(keyfile,password) char *keyfile; char *password; {
    
    SSL_METHOD *meth;
    SSL_CTX *ctx;

    if(!bio_err){
    
        /* Global system initialization*/
        SSL_library_init();
        SSL_load_error_strings();

        /* An error write context */
        bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
   }

    /* Create our context*/
    meth = SSLv23_method();
    ctx = SSL_CTX_new(meth);

    /* Load our keys and certificates*/
    if(!(SSL_CTX_use_certificate_chain_file(ctx, keyfile)))
    berr_exit("Can’t read certificate file");

    pass = password;
    SSL_CTX_set_default_passwd_cb(ctx, password_cb);
    if(!(SSL_CTX_use_PrivateKey_file(ctx, keyfile,SSL_FILETYPE_PEM)))
    berr_exit("Can’t read key file");
    
   /* Load the CAs we trust*/
   if(!(SSL_CTX_load_verify_locations(ctx, CA_LIST,0)))
   berr_exit("Ca’t read CA list");
   #if (OPENSSL_VERSION_NUMBER < 0x0090600fL)
   SSL_CTX_set_verify_depth(ctx,1);
   #endif

   return ctx;
 }

/******************************************************************************/

int setup_tcp(int port){
  int sock;
  struct sockaddr_in sin; //serv_addr in example
  int val=1;


  if((sock=socket(AF_INET,SOCK_STREAM,0))<0){
    perror("socket");
    close(sock);
    exit(0);
  }
  
  //setup sin
  memset(&sin,0,sizeof(sin));
  sin.sin_addr.s_addr=INADDR_ANY;
  sin.sin_family=AF_INET;
  sin.sin_port=htons(port);
  
  setsockopt(sock,SOL_SOCKET,SO_REUSEADDR, &val,sizeof(val));
    
  if(bind(sock,(struct sockaddr *)&sin, sizeof(sin))<0){
    perror("bind");
    close(sock);
    exit (0);
  }

  if(listen(sock,5)<0){
    perror("listen");
    close(sock);
    exit (0);
  }
  
  return sock;

}

/******************************************************************************/

void print_client_certification(ssl)
    SSL *ssl;
{
    X509 *peer;
    char peer_CN[256];
    char peer_email[256];

    /*Check the cert chain. The chain length
    42 is automatically checked by OpenSSL when
    43 we set the verify depth in the ctx */

    //extract certificate
    peer=SSL_get_peer_certificate(ssl);
    if((peer == NULL) || (SSL_get_verify_result(ssl)!=X509_V_OK)){
        printf(FMT_ACCEPT_ERR);
        ERR_print_errors_fp(stdout);   return;
    }

    //Get common name
    X509_NAME_get_text_by_NID
        (X509_get_subject_name(peer),NID_commonName, peer_CN, 256);

    //Get client email
    X509_NAME_get_text_by_NID
        (X509_get_subject_name(peer),NID_pkcs9_emailAddress, peer_email, 256);

    //Print it out and return
    printf(FMT_CLIENT_INFO, peer_CN, peer_email);
 
 }

/******************************************************************************/
    
void read_write_server(SSL *ssl, int s){

    int len;
    char buf[256];
    char *answer = "42";

    //read from SSL connection
    int r = SSL_read(ssl,buf,256);
    
    switch(SSL_get_error(ssl,r)){
        case SSL_ERROR_NONE:
            len=r;
            break;
        case SSL_ERROR_ZERO_RETURN:
            goto shutdown;
        case SSL_ERROR_SYSCALL:
            printf(FMT_INCOMPLETE_CLOSE);
            goto done;
        default:
            printf("SSL read error");
    }

    //write to ssl connection
    buf[r] = '\0';
    
    printf(FMT_OUTPUT, buf, answer);
    r = SSL_write(ssl,answer,strlen(answer));
    
    switch(SSL_get_error(ssl,r)){
        case SSL_ERROR_NONE:
            if(strlen(answer)!=r)
                printf("Incomplete write!");
            break;
        case SSL_ERROR_ZERO_RETURN:
            goto shutdown;
        case SSL_ERROR_SYSCALL:
            printf(FMT_INCOMPLETE_CLOSE);
            goto done;
        default:
            printf("SSL write problem");
    }

    shutdown:
    r = SSL_shutdown(ssl);
    
    if(!r){   
      /*If we called SSL_shutdown() first then
      we always get return value of ’0’. In
      this case, try again, but first send a
      TCP FIN to trigger the other side’s
      close_notify*/
      shutdown(s,1);
      r=SSL_shutdown(ssl);
    }

    switch(r)
    {
        case 1:
            break; /* Success */
        case 0:
        case -1:
        default:
            printf("Shutdown failed");
            //ber exit
    }

    done:
    SSL_free(ssl);
    close(s);
    return;
}

/******************************************************************************/
/***                                                                        ***/
/***                             Main Function                              ***/
/***                                                                        ***/
/******************************************************************************/

int main(int argc, char **argv){
    int s, r, sock, port = PORT;
    struct sockaddr_in sin;
    int val = 1;
    pid_t pid;
  
    /*Parse command line arguments*/
    switch(argc){
        case 1:    break;
        case 2:
            port=atoi(argv[1]);
            if (port<1||port>65535)
                {fprintf(stderr,"invalid port number");    exit(0);}
            break;
        default:
            printf("Usage: %s port\n", argv[0]); exit(0);
    }

    // Initialize SSL variables
    SSL_CTX *ctx;
  
    ctx = initialize_ctx(SERVER_KEY_FILE, SERVER_PASSWORD); 
    SSL_CTX_set_cipher_list(ctx, "SSLv2:SSLv3:TLSv1");
    
    //set verification mode for all to certificate based - TODO: unsure
    SSL_CTX_set_verify
        (ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);
  
    SSL *ssl; 
    BIO *sbio;
  
    sock = setup_tcp(port);
  
    while(1){
    
        // Wait for new connections
        // It returns a new file descriptor, and all communication on this 
        // connection should be done using the new file descriptor.
        if((s = accept(sock, NULL, 0))<0){
            perror("accept");          close(sock);
            close(s);                  exit(0);
        }
    
        /*Then fork a child to handle the connection*/
        if((pid=fork()))                   {close(s);}

        else {
            
            /*Child code*/

            //Create and set up a new SSL structure
            ssl = SSL_new(ctx);
            sbio = BIO_new_socket(s,BIO_NOCLOSE); //read and write socket BIO
            SSL_set_bio(ssl,sbio,sbio);

            //Initiate the SSL handshake with a client
            //printf("Initiating SSL handshake on server side:\n");
            r = SSL_accept(ssl);
            //printf ("SSL accept code: %d \n", r);
            
            if(r <= 0) {
                
                switch(SSL_get_error(ssl, r)) {
                    case SSL_ERROR_NONE:
                        //printf("ssl_error_none\n");
    			break;
                    case SSL_ERROR_ZERO_RETURN:
    			//printf("ssl_error_zero_return\n");
    			break;
                    case SSL_ERROR_SYSCALL:
    			//printf("ssl_error_syscall\n");
    			break;
                    case SSL_ERROR_SSL:
    			//printf("ssl_error_ssl\n");
    			break;
                    case SSL_ERROR_WANT_READ:
    			//printf("ssl_error_want_read\n");
    			break;
                    default:
    			printf("unknown error!\n");   break;
                }
			 
                printf(FMT_ACCEPT_ERR);
                ERR_print_errors_fp(stdout);  //unsure

                close(s);              exit(0);
            }
      
            print_client_certification(ssl);

            read_write_server(ssl,s);//read and write into ssl

            //graceful close at braches at read_write_server
            return 0;
        }
    }

  SSL_CTX_free(ctx);
  close(sock);
  return 1;
}