CC=clang

CFLAGS=-c -Wall

all: exe_parser

exe_parser: main.o file_worker.o parser.o
	$(CC) main.o file_worker.o parser.o -o exe_parser

main.o: main.c
	$(CC) $(CFLAGS) main.c

file_worker.o: file_worker.c
	$(CC) $(CFLAGS) file_worker.c

parser.o: parser.c
	$(CC) $(CFLAGS) parser.c

clean:
	rm -rf *.o exe_parser