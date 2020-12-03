all: pka2xml patch

.PHONY: pka2xml
pka2xml: pka2xml.cpp base64.cpp
	g++ -o pka2xml pka2xml.cpp base64.cpp -I/usr/local/include -L/usr/local/lib -lcryptopp -lz

.PHONY: patch
patch: patch.c
	gcc -o patch patch.c
