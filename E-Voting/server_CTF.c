#include <regex.h>
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
#include "uthash.h"
 
#define FAIL		-1
#define VOTED		2
#define REGISTERED	1
#define UNREGISTERED	0
#define REGEX_MATCH	1
#define REGEX_NOMATCH	0
#define CLA_PORT	20001
#define VOTE_CAP	5
#define VAL_CAP		1024

typedef struct voterNode {
  int id;
  int vote;
  int val;
  UT_hash_handle hh;
} voterNode;

typedef struct userNameNode {
  char name[10];
  UT_hash_handle hh;
} userNameNode;

userNameNode *NAME_TABLE = NULL;
voterNode *VOTE_TABLE = NULL;
int VAL_TABLE[VAL_CAP] = {UNREGISTERED};
int CANDIDATE_TABLE[3] = {0};
int vote_count = 0;

int OpenListener(int port) {
  int sd;
  struct sockaddr_in addr;
 
  sd = socket(PF_INET, SOCK_STREAM, 0);
  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = INADDR_ANY;
  if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
      perror("can't bind port");
      abort();
    }

  if ( listen(sd, 10) != 0 )
    {
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
 
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile) {
  /* set the local certificate from CertFile */
  if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 ) {
    ERR_print_errors_fp(stderr);
    abort();
  }
  /* set the private key from KeyFile (may be the same as CertFile) */
  if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 ) {
    ERR_print_errors_fp(stderr);
    abort();
  }
  /* verify private key */
  if ( !SSL_CTX_check_private_key(ctx) ) {
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
 
 
int valRegex( char *buf ) {
  regex_t regex;
  int ret;

  fprintf( stdout, "VAL REGEX Evaluating Message from Client: *%s*\n", buf );
  ret = regcomp( &regex, "^VAL [0-9][0-9][0-9][0-9] USER [[:alnum:]]", 0 );
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
 
int retrieveVal( char *buf ) {
  char val_string[5];
  int val;
  
  strncpy( val_string, buf + 4*sizeof(char), 4 );
  val_string[4] = '\0';
  fprintf( stdout, "valstring = %s\n", val_string );
  val = atoi( val_string );
  fprintf( stdout, "Retrieved Val No. %04d from CLA\n", val );
  if ( val >= 0 && val < VAL_CAP ) 
    return val;
  else 
    return 0;
}


char *retrieveName( char *buf ) {
  char *name_string = (char *)malloc( sizeof(char)*10 );

  strcpy( name_string, buf + 14*sizeof(char) );
  name_string[9] = '\0';
  fprintf( stdout, "name_string = *%s*\n", name_string );

  return name_string;
}

void storeNameNode ( char *buf ) {
  char *name_string = retrieveName( buf );
  userNameNode *new_node = (userNameNode *) malloc( sizeof(userNameNode) );
  
  strncpy( new_node->name, name_string, 9 );
  new_node->name[9] = '\0';
  HASH_ADD_STR( NAME_TABLE, name, new_node );

}

int valStatus( int val ) {
  if ( VAL_TABLE[val] == UNREGISTERED ) return UNREGISTERED;
  else if ( VAL_TABLE[val] == REGISTERED ) return REGISTERED;
  else if ( VAL_TABLE[val] >=0 && VAL_TABLE[val] < VAL_CAP ) return VOTED;
  else return FAIL;
}

void registerVal( int val ) {
  VAL_TABLE[val] = REGISTERED;
}

void printVoteStatus( void ) {
  int i;
  int curr;
  fprintf( stdout, "VOTE STATUS:\n" );
  for ( i = 0; i < VAL_CAP; i++ ) {
    curr = VAL_TABLE[i];
    if ( curr > 0 ) {
      if ( curr == REGISTERED )
	fprintf( stdout, "Val No. %d: REGISTERED\n", i );
      else if ( curr > REGISTERED ) 
	fprintf( stdout, "Val No. %d: VOTED\n", i );
    }
  }
}

void ServletCLA(SSL* ssl) { /* Serving CLA */
  char buf[1024];
  char reply[1024];
  int sd, bytes;
  int ret, val;

 
  if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
    ERR_print_errors_fp(stderr);
  else {
    ShowCerts(ssl);        /* get any certificates */
    bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
    if ( bytes > 0 ) {
      buf[bytes] = '\0';
      printf("Client msg:\"%s\"\n", buf);
      if ( valRegex( buf ) == REGEX_MATCH ) {
	fprintf( stdout, "CLA Message matched with REGEX\n" );
	val = retrieveVal( buf );
	if ( valStatus( val ) == UNREGISTERED ) {
	  registerVal( val );
	  storeNameNode( buf );
	  printVoteStatus( );
	}	
      }
      else {
	fprintf( stderr, "Unknown Message format from supposed CLA\n" );
      }
    }
    else
      ERR_print_errors_fp(stderr);
  }
  sd = SSL_get_fd(ssl);       /* get socket connection */
  SSL_free(ssl);         /* release SSL state */
  close(sd);          /* close connection */
}

voterNode *retrieveVoterNode( char *buf ) {
  voterNode *new_node = (voterNode *)malloc( sizeof(voterNode) );
  char *val_string = (char *)malloc( sizeof(char) * 5 );
  char *vote_string = (char *)malloc( sizeof(char) * 2 );
  char *id_string;
  int val;
  int vote;
  int id;

  strncpy( vote_string, (buf+5), 1 );
  vote_string[1] = '\0';
  vote = atoi( vote_string );

  strncpy( val_string, (buf+11), 4 );
  val_string[5] = '\0';
  val = atoi( val_string );
  
  id_string = (char *)malloc( sizeof(char) * strlen( buf+19 ) + 1 );
  strcpy( id_string, (buf+19) );
  id_string[strlen( buf+19 )] = '\0';
  id = atoi( id_string );

  new_node->id = id;
  new_node->val = val;
  new_node->vote = vote;

  return new_node;
}
 
int tabulateVote( voterNode *new_vote ) {
  voterNode *ptr = NULL;
  
  if ( !(new_vote->vote < 4 && new_vote->vote >= 0) ) return FAIL;
  if ( !(new_vote->val < VAL_CAP && new_vote->val >= 0) ) return FAIL;
  if ( VAL_TABLE[new_vote->val] != REGISTERED ) return FAIL;

  HASH_FIND_INT( VOTE_TABLE, &(new_vote->id), ptr );
  if ( ptr != NULL ) return FAIL;

  HASH_ADD_INT( VOTE_TABLE, id, new_vote );

  VAL_TABLE[new_vote->val] = VOTED;
  vote_count += 1;

  CANDIDATE_TABLE[new_vote->vote - 1] += 1;
  
  return 1;
}

void printNameList( void ) {
  userNameNode *tmp, *ptr;
  printf( "Voters:\n" );
  HASH_ITER( hh, NAME_TABLE, ptr, tmp ) {
    printf( "%s\n", ptr->name );
  }
}

void Servlet(SSL* ssl) { /* Serve the connection -- threadable */
  char buf[1024];
  char reply[1024];
  int sd, bytes, val;
  const char* HTMLecho="<html><body><pre>%s</pre></body></html>\n\n";
  voterNode *new_vote = NULL;

  if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
    ERR_print_errors_fp(stderr);
  else {
    ShowCerts(ssl);        /* get any certificates */
    bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
    if ( bytes > 0 ) {
      buf[bytes] = '\0';
      printf("Client msg:\"%s\"\n", buf);
      if ( voterRegex( buf ) == REGEX_MATCH ) {
	fprintf( stdout, "Voter Message matched with REGEX\n" );
	new_vote = retrieveVoterNode( buf );
	if ( tabulateVote( new_vote ) == FAIL ) {
	  sprintf(reply, "Unable to tabulate vote. Invalid Candidate Vote/Validation Number or Try a different ID\n");   /* construct reply */
	  SSL_write(ssl, reply, strlen(reply)); /* send reply */
	}
	printVoteStatus( );
      }
      else if ( valRegex( buf ) == REGEX_MATCH ) {
	fprintf( stdout, "CLA Message matched with REGEX\n" );
	val = retrieveVal( buf );
	if ( valStatus( val ) == UNREGISTERED ) {
	  registerVal( val );
	  storeNameNode( buf );
	  printVoteStatus( );
	  printNameList( );
	}	
      }
    }
    else
      ERR_print_errors_fp(stderr);
  }
  sd = SSL_get_fd(ssl);       /* get socket connection */
  SSL_free(ssl);         /* release SSL state */
  close(sd);          /* close connection */
}

void printResults( void ) {
  voterNode *tmp, *ptr;
  printf( "########### RESULTS ############\n" );
  HASH_ITER( hh, VOTE_TABLE, ptr, tmp ) {
    printf("id %d: voted for %d\n", ptr->id, ptr->vote);
  }
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
  LoadCertificates(ctx, "CTF_cert.pem", "CTF_cert.pem"); /* load certs */
  server = OpenListener(atoi(portnum));    /* create server socket */
  while (1) {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    SSL *ssl;
 
    int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
    printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
    ssl = SSL_new(ctx);              /* get new SSL state with context */
    SSL_set_fd(ssl, client);      /* set connection socket to SSL state */

    //    if ( ntohs( addr.sin_port ) == CLA_PORT ) { /* Check if incoming CLA connection */
      //      fprintf( stdout, "CLA MESSAGE\n" );
      //      ServletCLA( ssl );
      //    }
    //    else { 
      //      fprintf( stdout, "VOTER MESSAGE\n" );
      Servlet(ssl);         /* service connection */
      //    }
    
    if ( vote_count == VOTE_CAP ) {
      printf( "VOTE CAP REACHED:\n" );
      printResults( );
      printNameList( );
      break;
    }
  }

  SSL_CTX_free(ctx);         /* release context */

}
