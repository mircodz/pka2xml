Convert Packet Tracer network simulation pka and pkt files into XML and vice versa.

For more information you can read [this short blog post](https://mircodezorzi.github.io/doc/reversing-packet-tracer/) that explains how I managed to write the utility.

## Coming Soon
- Patches for versions other than 7.3.1 on linux
- UI version
- Reverse module encryption algorithm

## Building
### Building with Docker
```
docker build -t pka2xml:1.0.0 . && docker run -it pka2xml:1.0.0
```

### Building manually
To build a static binary:

```
make static-install
```

To build a dynamic binary:
```
make dynamic-install
```

## `pka2xml`
```
usage: pka2xml [ options ]

where options are:
  -d <in> <out>   decrypt pka/pkt to xml
  -e <in> <out>   encrypt pka/pkt to xml

  -f <in> <out>   allow packet tracer file to be read by any version

  -nets <in>      decrypt packet tracer "nets" file
  -logs <in>      decrypt packet tracer log file

  --forge <out>   forge authentication file to bypass login


examples:
  pka2xml -d foobar.pka foobar.xml
  pka2xml -e foobar.xml foobar.pka
  pka2xml -nets $HOME/packettracer/nets
  pka2xml -logs $HOME/packettracer/pt_12.05.2020_21.07.17.338.log
```

## `PacketTracer` (`patch.c`)
Launch PacketTracer with the following patches:
- bypass login screen
- display all activities as completed
- unlock all previously locked interfaces
- don't reset activity on user change

## `graph.py`
Given an xml file of a Packet Tracer Network Simulation, generates a graph of the entire network.

![](https://raw.githubusercontent.com/mircodezorzi/pka2xml/master/examples/network.png)

## Dependencies
- CryptoPP
- libzip
- Re2
