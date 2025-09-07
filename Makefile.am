# Files to put into source package
EXTRA_DIST = src/*.h BUGS CHANGES KNOWN-BUGS img/* lib/* RFCs/* docs/*

SUBDIRS = src
ACLOCAL_AMFLAGS = -Im4

BIN_DISTDIR = $(PACKAGE_NAME)-$(PACKAGE_VERSION)

.PHONY: install-bin-local binary-dist

install-bin-local:
	$(MAKE) -C src install-bin-local

binary-dist:
	$(MAKE) install-bin-local
	@ABS_DISTDIR=$$(pwd)/$(BIN_DISTDIR); \
	tar cvfz $(PACKAGE_NAME)-$(PACKAGE_VERSION)-bin.tar.gz -C $$ABS_DISTDIR .; \
	rm -rf $$ABS_DISTDIR
