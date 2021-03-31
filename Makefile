.PHONY: all
all: static-install

.PHONY: static-install
static-install: pka2xml-static patch-static install

.PHONY: static-install-docker
static-install-docker: pka2xml-static-docker patch-static install

.PHONY: dynamic-install
dynamic-install: pka2xml-dynamic patch-dynamic install

.PHONY: pka2xml-static
pka2xml-static: main.cpp
	g++ -o pka2xml main.cpp -I/usr/local/include /usr/lib/libz.a /usr/local/lib/libre2.a /usr/local/lib/libcryptopp.a -lpthread -static -static-libstdc++

.PHONY: pka2xml-static-docker
pka2xml-static-docker: main.cpp
	g++ -o pka2xml main.cpp -I/usr/include /usr/lib/x86_64-linux-gnu/libz.a /usr/lib/x86_64-linux-gnu/libre2.a /usr/lib/x86_64-linux-gnu/libcryptopp.a -lpthread -static -static-libstdc++

.PHONY: pka2xml-dynamic
pka2xml-dynamic: main.cpp
	g++ -o pka2xml main.cpp -I/usr/local/include -L/usr/local/lib -lcryptopp -lz -lre2

.PHONY: patch-static
patch-static: patch.c
	gcc -o patch patch.c -static -static-libgcc

.PHONY: patch-dynamic
patch-dynamic: patch.c
	gcc -o patch patch.c

install:
	cp patch /usr/local/bin/PacketTracer
	cp pka2xml /usr/local/bin

clean:
	rm patch pka2xml
