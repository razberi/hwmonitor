APPNAME=hwmonitor

CC=gcc
INCLUDE=$(shell pkg-config --cflags libusb-1.0) $(shall pkg-config --cflags json-c) -I.
LDLIBS=$(shell pkg-config --libs libusb-1.0) $(shell pkg-config --libs json-c) -lpthread
CFLAGS=$(INCLUDE) -z muldefs -std=gnu99

# by default set dest dir to root
# deb pkg maker will set it to a temp dir while creating a package
DESTDIR ?= ""
INSTALLDIR=$(DESTDIR)/usr/local/razberi/

# requires git, used to make distribution source tarball
# for creating packages with, variables are evaluated when
# the dist target is run so systems without git can still `make`
REPONAME=$(shell basename `git rev-parse --show-toplevel`)
VERSION=$(shell git describe --abbrev=0 | sed s/^v//)
BRANCH=master

$(APPNAME): HWInterface.c HIDCP2112.c
	$(CC) -o $@ $^ $(CFLAGS) $(LDLIBS)

.PHONY: all
all: $(APPNAME)

.PHONY: clean
clean: 
	rm -f *.o $(APPNAME)

.PHONY: install
install:
	@# copy files to destinations
	install -d $(INSTALLDIR)
	cp $(APPNAME) $(INSTALLDIR)

.PHONY: dist
dist:
	git archive --prefix='$(REPONAME)-$(VERSION)/' -o $(REPONAME)_$(VERSION).orig.tar.gz -9 refs/heads/$(BRANCH)

.PHONY: distclean
distclean: clean
	rm -f *.orig.tar.gz
