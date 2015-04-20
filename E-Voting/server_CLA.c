#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <pthread.h>
#include "uthash.h"
#include <stdio.h>
#include <netdb.h>
 
 
#define FAIL		-1
#define CAP		1024
#define CTF_PORT	30000
#define CLA_PORT	20001

typedef struct Validation {
  char name[10];
  int val;
  UT_hash_handle hh;
} Validation;


Validation * VALIDATION_TABLE = NULL;  
int USED_VALS[1024] = {1};
int bound = 0;
pthread_mutex_t table_lock;

int OpenConnection( const char *hostname, int port ) {
  int sd;
  struct hostent *host;
  struct sockaddr_in addr, h_addr;
 
  if ( (host = gethostbyname(hostname)) == NULL ) {
    perror(hostname);
    abort();
  }

  sd = socket( PF_INET, SOCK_STREAM, 0 );
  if ( sd == FAIL ) {
    fprintf( stderr, "ERROR ON CREATING SOCKET\n" );
  }

  memset(&h_addr, 0, sizeof(h_addr));
  h_addr.sin_family = AF_INET;
  h_addr.sin_port = htons(CLA_PORT);
  h_addr.sin_addr.s_addr = INADDR_ANY;


  printf( "Attempting Binding, fd = %d\n", sd );
  if ( bound == 0 ) {
    bound = 1;
    if ( bind( sd, (struct sockaddr *) &h_addr, sizeof(h_addr) ) != 0 ) 
      error("ERROR on binding\n");
  }
  
  printf( "Attempting Connection\n" );
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(CTF_PORT);
  addr.sin_addr.s_addr = *(long*)(host->h_addr);


  if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ) {
    close(sd);
    perror(hostname);
    //    abort();
  }

  return sd;
}

int OpenListener(int port) { 
  int sd;
  struct sockaddr_in addr;
 
  sd = socket(PF_INET, SOCK_STREAM, 0);
  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = INADDR_ANY;
  if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ) {
      perror("can't bind port");
      abort();
  }
  if ( listen(sd, 10) != 0 ) {
      perror("Can't configure listening port");
      abort();
  }
  return sd;
}
 
SSL_CTX* InitServerCTX(void) {
  SSL_METHOD *method;
  SSL_CTX *ctx;
 
  OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
  SSL_load_error_strings();   /* load all error messages */
  method = SSLv23_server_method();  /* create new server-method instance */
  ctx = SSL_CTX_new(method);   /* create new context from method */
  if ( ctx == NULL )
    {
      ERR_print_errors_fp(stderr);
      abort();
    }
  return ctx;
}

SSL_CTX* InitCTX(void) {
  SSL_METHOD *method;
  SSL_CTX *ctx;
 
  OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
  SSL_load_error_strings();   /* Bring in and register error messages */
  method = SSLv23_client_method();  /* Create new client-method instance */
  ctx = SSL_CTX_new(method);   /* Create new context */
  if ( ctx == NULL ) {
    ERR_print_errors_fp(stderr);
    abort();
  }
  return ctx;
}
 
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
  /* set the local certificate from CertFile */
  if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
      ERR_print_errors_fp(stderr);
      abort();
    }
  /* set the private key from KeyFile (may be the same as CertFile) */
  if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
      ERR_print_errors_fp(stderr);
      abort();
    }
  /* verify private key */
  if ( !SSL_CTX_check_private_key(ctx) )
    {
      fprintf(stderr, "Private key does not match the public certificate\n");
      abort();
    }
}
 
void ShowCerts(SSL* ssl) {
  X509 *cert;
  char *line;
 
  cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
  if ( cert != NULL ) {
      printf("Server certificates:\n");
      line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
      printf("Subject: %s\n", line);
      free(line);
      line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
      printf("Issuer: %s\n", line);
      free(line);
      X509_free(cert);
  }
  else
    printf("No certificates.\n");
}

void valActivate( int dump ) {
  USED_VALS[dump] = 1;
}

void valDeactivate( int dump ) {
  USED_VALS[dump] = 0;
}

int getVal( void ) {
  int dump = 0;

  while ( USED_VALS[dump] == 1 ) {
    dump = rand() % CAP;
  }

  return dump;
}

Validation *createValidation( int valnum, char *name ) {

  Validation *dump;
  char *msg = (char *)malloc( strlen(name)/sizeof(char) + 15 );
  dump = (Validation *)malloc( sizeof (Validation) );
  dump->val = valnum;
  strncpy( dump->name, name, 9 );
  dump->name[9] = '\0';

  /* Send new Valnum to CTF */
  SSL_CTX *ctx;
  int sd;
  SSL *ssl;
  ctx = InitCTX();
  sd = OpenConnection( "127.0.0.1", CTF_PORT );

  ssl = SSL_new(ctx);      /* create new SSL connection state */
  SSL_set_fd(ssl, sd);    /* attach the socket descriptor */
  if ( SSL_connect(ssl) == FAIL ) {  /* perform the connection */
    ERR_print_errors_fp( stderr );
    close(sd);         /* close socket */
    SSL_CTX_free(ctx);        /* release context */  
    return NULL;
  }
  else {
    sprintf( msg, "VAL %04d USER %s", valnum, name );
    msg[strlen(name)/sizeof(char) + 14] = '\0';
    printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
    ShowCerts( ssl );        /* get any certs */
    SSL_write( ssl, msg, strlen(msg) );   /* encrypt & send message */
    SSL_free(ssl);        /* release connection state */
  }

  fprintf( stdout, "Closing socket descriptor: %d\n", sd );
  close(sd);         /* close socket */
  SSL_CTX_free(ctx);        /* release context */  

  return dump;
}
 
int registered( char *name ) {
  Validation *lookup = NULL;
  //fprintf( stdout, "Searching for: *%s*\n", name );

  HASH_FIND_STR( VALIDATION_TABLE, name, lookup );
  
  if ( lookup == NULL ) 
    return 0;
  else 
    return 1;
}

int registerUser( char *name, Validation **temp ) {
  int valnum;
  Validation *dump;

  dump = (Validation *) malloc ( sizeof(Validation) );
  valnum = getVal();
  dump = createValidation( valnum, name );
  if ( dump == NULL ) {
    free(dump);
    return 0;
  }

  valActivate( valnum );
  //printf( "strcmp buf, temp->name: %d.... buf = *%s*, temp->name = *%s*\n", strcmp( buf, temp->name ), buf, temp->name );
  HASH_ADD_STR( VALIDATION_TABLE, name, dump );
  *temp = dump;
  fprintf( stdout, "Validation No. %d\n", valnum );
  return 1;
}

void Servlet(SSL* ssl) /* Serve the connection -- threadable */
{
  char buf[1024];
  char reply[1024];
  int sd, bytes;
  int valnum = -1;
  Validation *temp;
 
  if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
    ERR_print_errors_fp(stderr);
  else {
    ShowCerts(ssl);        /* get any certificates */
    bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
       
    if ( bytes > 0 ) {

      buf[bytes] = 0;
      printf("Client msg: \"%s\"\n", buf);
      //printf( "strcmp buf, Hello???: %d\n", strcmp( buf, "Hello???" ) );

      if ( !registered( buf ) ) {
	fprintf( stdout, "New User: %s\n", buf );
	if ( registerUser( buf, &temp ) )
	  sprintf( reply, "Validation No. %d\n Vote for 1. Ravioli, 2. Spinach, 3. Mango", temp->val );
	else 
	  sprintf( reply, "Cannot Register User at this moment. Try again later." );
      }
      else {
	sprintf( reply, "Validation No. already issued to voter" );
      }
      SSL_write(ssl, reply, strlen(reply)); /* send reply */
    }
    else
      ERR_print_errors_fp(stderr);
  }
  sd = SSL_get_fd(ssl);       /* get socket connection */

  close(sd);          /* close connection */
}
 

int main(int count, char *strings[]) {
  SSL_CTX *ctx;
  int server;
  char *portnum;
 
  if ( count != 2 ) {
    printf("Usage: %s <portnum>\n", strings[0]);
    exit(0);
  }
  SSL_library_init();
 
  portnum = strings[1];
  ctx = InitServerCTX();        /* initialize SSL */
  LoadCertificates(ctx, "CLA_cert.pem", "CLA_cert.pem"); /* load certs */
  server = OpenListener(atoi(portnum));    /* create server socket */
  while (1) { 
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    SSL *ssl;
 
    int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
    printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
    ssl = SSL_new(ctx);              /* get new SSL state with context */
    SSL_set_fd(ssl, client);      /* set connection socket to SSL state */
    Servlet(ssl);         /* service connection */
  }
  close(server);          /* close server socket */
  SSL_CTX_free(ctx);         /* release context */
}
