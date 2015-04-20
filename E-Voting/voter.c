#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <regex.h>
 
#define FAIL    -1
#define REGEX_NOMATCH 0
#define REGEX_MATCH 1 
int OpenConnection(const char *hostname, int port) {
  int sd;
  struct hostent *host;
  struct sockaddr_in addr;
 
  if ( (host = gethostbyname(hostname)) == NULL ) {
    perror(hostname);
    abort();
  }

  sd = socket(PF_INET, SOCK_STREAM, 0);
  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = *(long*)(host->h_addr);
  if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ) {
    close(sd);
    perror(hostname);
    abort();
  }
  return sd;
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
 
void ShowCerts(SSL* ssl) {
  X509 *cert;
  char *line;
 
  cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
  if ( cert != NULL ) {
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
    printf("No certificates.\n");
}

int voterRegex( char *buf ) {
  regex_t regex;
  int ret;

  fprintf( stdout, "VOTER REGEX Evaluating Message from Client\n" );
  ret = regcomp( &regex, "^VOTE [0-9] VAL [0-9][0-9][0-9][0-9] ID [0-9][0-9][0-9][0-9]", 0 );
  if ( ret ) 
    fprintf( stderr, "Could not compile regex\n" );
  else {
    fprintf( stdout, "Attempting to Match: %s\n", buf );
    ret = regexec( &regex, buf, 0, NULL, 0 );
    if ( ret == 0 ) {
      fprintf( stdout, "Matched\n" );
      return REGEX_MATCH;
    }
    else if ( ret == REG_NOMATCH ) {
      fprintf( stdout, "No Match\n" );
      return REGEX_NOMATCH;
    }
    else {
      regerror( ret, &regex, buf, strlen(buf) );
      fprintf( stderr, "Regex Match error\n" );
    }
  }

  regfree( &regex );
  return REGEX_NOMATCH;
}
 
void printHelp( void ) {
  fprintf( stdout, "To request a Validation Number, type: REQUEST VAL\n" );
  fprintf( stdout, "To send a vote, type: VOTE <candidate number> VAL <4 digit validation number> ID <your random 4 digit id number>\n" );
}

int main(int count, char *strings[]) {
  SSL_CTX *ctx;
  int server;
  SSL *ssl;
  char buf[1024];
  char word[1024];
  char recipient[1024];
  int bytes;
  char *hostname, *CLA_portnum, *CTF_portnum;
  char *msg;
 
  if ( count != 4 ) {
    printf("Usage: %s <hostname> <CLA portnum> <CTF portnum>\n", strings[0]);
    exit(0);
  }
  SSL_library_init();
  hostname=strings[1];
  CLA_portnum=strings[2];
  CTF_portnum=strings[3];

  fprintf( stdout, "Please enter your username: " );
  
  gets( recipient );

  while ( 1 ) {
    fprintf( stdout, "For help type 'h' or 'q' to quit\n" );

    gets( word );

    if ( strcmp( word, "h" ) == 0 ) {
      printHelp();
      continue;
    }
    if ( strcmp( word, "q" ) == 0 ) {
      return 0;
    }

    fprintf( stdout, "You entered:*%s*\n", word );
 
    if ( strcmp( word, "REQUEST VAL" ) == 0 ) {
      fprintf( stdout, "REQUESTING VALIDATION NUMBER FROM CLA\n" );
      ctx = InitCTX();
      server = OpenConnection(hostname, atoi(CLA_portnum));
      ssl = SSL_new(ctx);      /* create new SSL connection state */
      SSL_set_fd(ssl, server);    /* attach the socket descriptor */
      if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
	ERR_print_errors_fp( stderr );
      else {
	msg = recipient;
 
	printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
	ShowCerts( ssl );        /* get any certs */
	SSL_write( ssl, msg, strlen(msg) );   /* encrypt & send message */
	bytes = SSL_read( ssl, buf, sizeof(buf) ); /* get reply & decrypt */
	buf[bytes] = '\0';
	printf("Result: %s\n", buf);
	SSL_free(ssl);        /* release connection state */
      }

      close(server);         /* close socket */
      SSL_CTX_free(ctx);        /* release context */

    }
    else if ( voterRegex( word ) == REGEX_MATCH ) {
      fprintf( stdout, "SENDING VOTE INFORMATION TO CTF\n" );
      ctx = InitCTX();
      server = OpenConnection(hostname, atoi(CTF_portnum));
      ssl = SSL_new(ctx);      /* create new SSL connection state */
      SSL_set_fd(ssl, server);    /* attach the socket descriptor */
      if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
	ERR_print_errors_fp( stderr );
      else {
	msg = word;
 
	printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
	ShowCerts( ssl );        /* get any certs */
	SSL_write( ssl, msg, strlen(msg) );   /* encrypt & send message */
	bytes = SSL_read( ssl, buf, sizeof(buf) ); /* get reply & decrypt */
	buf[bytes] = '\0';
	printf("Result: %s\n", buf);
	SSL_free(ssl);        /* release connection state */
      }

      close(server);         /* close socket */
      SSL_CTX_free(ctx);        /* release context */

    }      
    
  }

  return 0;
}
