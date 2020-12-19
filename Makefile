all: pka2xml patch

.PHONY: pka2xml
pka2xml: pka2xml.cpp
	g++ -o pka2xml pka2xml.cpp -I/usr/local/include -L/usr/local/lib -lcryptopp -lz -lre2

.PHONY: patch
patch: patch.c
	gcc -o patch patch.c

install: patch pka2xml
	cp patch /usr/local/bin/PatchedTracer
	cp pka2xml /usr/local/bin
