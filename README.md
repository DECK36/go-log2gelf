go-log2gelf
===========

A simple daemon that reads a file (tail -f style)
and sends every line as GELF 1.1 message via UDP.
(Basically a combination of https://github.com/DECK36/go-log2amqp and
https://github.com/DECK36/go-amqp2gelf, but without the AMQP transport.)

Uses https://github.com/ActiveState/tail to read files
and https://github.com/DECK36/go-gelf to format GELF.

Intended for nginx and apache access logs -- so it does some special character
encoding/escaping for that format (because `\xXX` is not valid JSON).

```
Usage of ./go-log2gelf:
  -file="/var/log/syslog": filename to watch
  -n=false: Quit after file is read, do not wait for more data, do not read/write state
  -port=12201: Graylog2 GELF/UDP port
  -server="localhost": Graylog2 server
  -v=false: Verbose output
```

Package example
---------------

The `ubuntu` directory contains an example how to package this tool:
`build.sh` will fetch all sources, compile them, and use
[fpm](https://github.com/jordansissel/fpm) to build a Debian package
containing the binary, the configuration, and the upstart config.
