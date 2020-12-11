For more information read [this blog post](https://mircodezorzi.github.io/posts/packettracer/).

## Building and Installing
```
make
make install
```

## `pka2xml`
```
usage: pka2xml [ options ]

where options are:
  -d <in> <out>      decrypt pka/pkt to xml
  -e <in> <out>      decrypt pka/pkt to xml
  -nets <in>         decrypt packet tracer "nets" file
  -logs <in>         decrypt packet tracer log file
  -f --forge <out>   forge authentication file to bypass login

examples:
  pka2xml -d foobar.pka foobar.xml
  pka2xml -e foobar.xml foobar.pka
  pka2xml -nets $HOME/packettracer/nets
  pka2xml -logs pt_12.05.2020_21.07.17.338.log
```

## `PatchedTracer` (`patch.c`)
Launch PacketTracer, automatically applying patches to bypass the login screen, unlocking all the interafces and display all tasks as complete (in case a `pka` file is open).

## `graph`
Given an xml file of a Packet Tracer Network Simulation, generates a graph of the entire network.

![](https://raw.githubusercontent.com/mircodezorzi/pka2xml/master/examples/network.png)

## Dependencies
- CryptoPP
