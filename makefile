CC=gcc
INCLUDE=$(shell pkg-config --cflags libusb-1.0) $(shall pkg-config --cflags json-c) -I.
LDLIBS=$(shell pkg-config --libs libusb-1.0) $(shell pkg-config --libs json-c) -lpthread
CFLAGS=$(INCLUDE) -z muldefs -std=gnu99

# by default set dest dir to root
# deb pkg maker will set it to a temp dir while creating a package
DESTDIR ?= ""
INSTALLDIR=$(DESTDIR)/usr/local/razberi/

hwmonitor: HWInterface.c HIDCP2112.c
	$(CC) -o $@ $^ $(CFLAGS) $(LDLIBS)

.PHONY: all
all: hwmonitor

.PHONY: clean
clean: 
	rm -f *.o hwmonitor

.PHONY: install
install:
	# copy files to destinations
	install -d $(INSTALLDIR)
	cp hwmonitor $(INSTALLDIR)

