For more information read [this blog post](https://mircodezorzi.github.io/posts/packettracer/).

## Building
```
make
```

## `pka2xml`
```
# Decrypt pka file into xml
$ pka2xml -d foo.pka foo.xml

# Encrypt xml file into pka
$ pka2xml-e foo.pka foo.xml
```

## `patch`
Launch PacketTracer, automatically applying patches to bypass the login screen, unlocking all the interafces and display all tasks as complete (in case a `pka` file is open).
