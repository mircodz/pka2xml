all: parser patch

.PHONY: parser
parser: parser.cpp base64.cpp
	g++ -o parser parser.cpp base64.cpp -I/usr/local/include -L/usr/local/lib -lcryptopp -lz

.PHONY: patch
patch: patch.c
	gcc -o patch patch.c
