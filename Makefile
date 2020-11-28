.PHONY: parser
parser:
	g++ -o parser parser.cpp base64.cpp -I/usr/local/include -L/usr/local/lib -lcryptopp -lz

.PHONY: patch
patch:
	gcc -o patch patch.c

all: patch parser
