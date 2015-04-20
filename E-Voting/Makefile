CC=gcc
CFLAGS=-g
LDFLAGS=-lcrypto -lssl

all: CLA CTF voter

CLA: server_CLA.c
	$(CC) $(CFLAGS) -o CLA server_CLA.c $(LDFLAGS)

CTF: server_CTF.c
	$(CC) $(CFLAGS) -o CTF server_CTF.c $(LDFLAGS)

voter: voter.c
	$(CC) $(CFLAGS) -o voter voter.c $(LDFLAGS)

clean:
	rm -f CLA CTF voter