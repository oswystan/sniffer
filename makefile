#######################################################################
##                     Copyright (C) 2020 wystan
##
##       filename: makefile
##    description: 
##        created: 2020-11-14 10:44:36
##         author: wystan
## 
#######################################################################
.PHONY: all build test install doc

src := $(shell find . -d 1 -name '*.go')

sniffer: $(src)
	go build -mod vendor -o $@
clean:
	rm -f sniffer

#######################################################################
