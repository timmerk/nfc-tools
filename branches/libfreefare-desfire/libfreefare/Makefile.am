
AM_CFLAGS = @LIBNFC_CFLAGS@
AM_LDFLAGS = @LIBNFC_LIBS@

lib_LTLIBRARIES = libfreefare.la

# TODO: Remove hexdump.c
# XXX: Remove hexdump.c on systems with a hexdump(1) function in libutil.
libfreefare_la_SOURCES = freefare.c \
			 hexdump.c \
			 mifare_classic.c \
			 mifare_ultralight.c \
			 mifare_desfire.c \
			 mifare_desfire_aid.c \
			 mifare_desfire_authenticate.c \
			 mifare_desfire_key.c \
			 mad.c \
			 desfire_error.c \
			 mifare_application.c

# TODO: Remove this
# XXX: Uncomment on FreeBSD to link with libutil which provides hexdump(1).
# libfreefare_la_LIBADD = -lutil

libfreefare_la_HEADERS = freefare.h
libfreefare_ladir = $(includedir)

EXTRA_DIST = freefare_internal.h
