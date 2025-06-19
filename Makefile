# Default compiler flags
CC ?= cc
CFLAGS ?= -Wall -O2
LDFLAGS ?= -flto=auto
LDLIBS ?=

#Default installation paths (may be overridden by environment variables)
prefix ?= /usr/local
exec_prefix ?= $(prefix)
sbindir ?= $(exec_prefix)/sbin
datarootdir ?= $(prefix)/share
mandir ?= $(datarootdir)/man
man5dir ?= $(mandir)/man5
man5ext ?= .5
man8dir ?= $(mandir)/man8
man8ext ?= .8

INSTALL ?= install
INSTALL_PROGRAM ?= $(INSTALL)
INSTALL_DATA ?= $(INSTALL) -m 644

GIT ?= git

TAYGA_VERSION = $(shell $(GIT) describe --tags --dirty)
TAYGA_BRANCH  = $(shell $(GIT) describe --all --dirty)
TAYGA_COMMIT  = $(shell $(GIT) rev-parse HEAD)

HEADERS := tayga.h list.h version.h
SOURCES := nat64.c addrmap.c dynamic.c tayga.c conffile.c

.PHONY: all clean install

all: tayga

check:
	echo $(INSTALL)

tayga: $(HEADERS) $(SOURCES)
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $(SOURCES) $(LDLIBS)

clean:
	$(RM) tayga version.h

installdirs:
	mkdir -p $(DESTDIR)$(sbindir) $(DESTDIR)$(man5dir) $(DESTDIR)$(man8dir)

install: installdirs
	$(INSTALL_PROGRAM) tayga $(DESTDIR)$(sbindir)/tayga
	-$(INSTALL_DATA) tayga.8 $(DESTDIR)$(man8dir)/tayga$(man8ext)
	-$(INSTALL_DATA) tayga.conf.5 $(DESTDIR)$(man5dir)/tayga.conf$(man5ext)

uninstall:
	$(RM) $(DESTDIR)$(sbindir)/tayga
	$(RM) $(DESTDIR)$(man8dir)/tayga$(man8ext)
	$(RM) $(DESTDIR)$(man5dir)/tayga.conf$(man5ext)

ifndef RELEASE
version.h:
	@echo "#define TAYGA_VERSION \"$(TAYGA_VERSION)\"" > version.h
	@echo "#define TAYGA_BRANCH \"$(TAYGA_BRANCH)\"" >> version.h
	@echo "#define TAYGA_COMMIT \"$(TAYGA_COMMIT)\"" >> version.h
endif
