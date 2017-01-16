CC=gcc
CFLAGS=-Wall -Os

aesgcm.out: aes.o gcm.o main.o
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -f aesgcm.out
	rm -f *.o
