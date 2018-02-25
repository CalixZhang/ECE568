#include "sharedssl.h"

#define HOST "localhost"
#define PORT 8765

#define CN_SERVER "Bob's Server"
#define EMAIL "ece568bob@ecf.utoronto.ca"
#define CLIENTKEYFILE "alice.pem"
#define CLIENTPASSWORD "password"
#define SERVER_KEY_FILE "bob.pem"
#define SERVER_PASSWORD "password"
#define CA_LIST "568ca.pem"

/* use these strings to tell the marker what is happening */
#define FMT_CONNECT_ERR "ECE568-CLIENT: SSL connect error\n"
#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"
#define FMT_CN_MISMATCH "ECE568-CLIENT: Server Common Name doesn't match\n"
#define FMT_EMAIL_MISMATCH "ECE568-CLIENT: Server Email doesn't match\n"
#define FMT_NO_VERIFY "ECE568-CLIENT: Certificate does not verify\n"
#define FMT_INCORRECT_CLOSE "ECE568-CLIENT: Premature close\n"

#define FMT_ACCEPT_ERR "ECE568-SERVER: SSL accept error\n"
#define FMT_CLIENT_INFO "ECE568-SERVER: %s %s\n"
#define FMT_INCOMPLETE_CLOSE "ECE568-SERVER: Incomplete shutdown\n"


BIO *bio = 0;
char *pass;

int std_exit(string)
  char *string;
  {
    fprintf(stderr,"%s\n",string);
    exit(0);
  }

int ssl_exit(string)
  char *string;
  {
    BIO_printf(bio,"%s\n",string);
    ERR_print_errors(bio);
    exit(0);
  }

void init_ssl(void){
  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();
  return;
}

static int password_cb(char *buf,int num,
  int rwflag,void *userdata)
  {
    if(num<strlen(pass)+1)
      return(0);

    strcpy(buf,pass);
    return(strlen(pass));
  }

int init_certs(char *keyfile, char *password){
    SSL_METHOD *meth;
    SSL_CTX *ctx;

    if(!bio){
        /* Global system initialization*/
    	init_ssl();

        /* An error write context */
        bio=BIO_new_fp(stderr,BIO_NOCLOSE);
   }

    /* Create our context*/
    meth = SSLv23_method();
    ctx = SSL_CTX_new(meth);

    /* Load our keys and certificates*/
    if(!(SSL_CTX_use_certificate_chain_file(ctx, keyfile)))
    ssl_exit("Can’t read certificate file");

    pass = password;
    SSL_CTX_set_default_passwd_cb(ctx, password_cb);
    if(!(SSL_CTX_use_PrivateKey_file(ctx, keyfile,SSL_FILETYPE_PEM)))
    ssl_exit("Can’t read key file");
    
   /* Load the CAs we trust*/
   if(!(SSL_CTX_load_verify_locations(ctx, CA_LIST,0)))
   ssl_exit("Ca’t read CA list");
   #if (OPENSSL_VERSION_NUMBER < 0x0090600fL)
   SSL_CTX_set_verify_depth(ctx,1);
   #endif

   return ctx;
}

void show_cert(SSL* ssl){   
    X509 *peer;
    char peer_CN[256];
    char peer_email[256];

    /*Check the cert chain. The chain length
    42 is automatically checked by OpenSSL when
    43 we set the verify depth in the ctx */

    //extract certificate
    peer=SSL_get_peer_certificate(ssl);
    if((peer == NULL) || (SSL_get_verify_result(ssl)!=X509_V_OK)){
        printf(FMT_CONNECT_ERR);
        ERR_print_errors_fp(stdout);   return;
    }

    X509_NAME_get_text_by_NID
        (X509_get_subject_name(peer),NID_commonName, peer_CN, 256);

    X509_NAME_get_text_by_NID
        (X509_get_subject_name(peer),NID_pkcs9_emailAddress, peer_email, 256);

    printf(FMT_SERVER_INFO, peer_CN, peer_email);
}