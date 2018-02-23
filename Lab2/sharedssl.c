#include "sharedssl.h"

void init_ssl(void){
  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();
  return;
}

int init_certs(SSL_CTX *ssl_ctx, char *cert_name){
  //set the certificate/private key for the client/server to use
  if(!(SSL_CTX_use_certificate_chain_file(ssl_ctx,cert_name))){
    printf("Can't read certificate file");
    return -1;
  }
  if(!(SSL_CTX_use_PrivateKey_file(ssl_ctx, cert_name,SSL_FILETYPE_PEM))){
    printf("Can't read key file");
    return -1;
  }
  return 0;
}

void show_cert(SSL* ssl){   
	X509 *cert;
    char *line;
 
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("Info: No client certificates configured.\n");
}