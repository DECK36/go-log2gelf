#! /bin/bash -ex

TMP=`mktemp -d`
export GOPATH=$TMP
go get github.com/DECK36/go-log2gelf
go build github.com/DECK36/go-log2gelf

cp $TMP/bin/go-log2gelf ./log2gelf

fpm -s dir -t deb --verbose \
	-n deck36-log2gelf --version 0.1 --iteration 1 \
	--url https://github.com/DECK36/go-log2gelf \
	--maintainer "Martin Schuette <martin.schuette@deck36.de>" \
	--prefix /usr/local/bin \
	--deb-default log2gelf.default \
	--deb-upstart log2gelf.upstart \
	log2gelf

