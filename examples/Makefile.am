AM_CFLAGS = -I. -I$(top_srcdir)/libfreefare @LIBNFC_CFLAGS@
AM_LDFLAGS = @LIBNFC_LIBS@

bin_PROGRAMS = mifare-classic-format mifare-desfire-format mifare-desfire-info

mifare_classic_format_SOURCES = mifare-classic-format.c
mifare_classic_format_LDADD = -lnfc $(top_builddir)/libfreefare/libfreefare.la -lssl

mifare_desfire_format_SOURCES = mifare-desfire-format.c
mifare_desfire_format_LDADD = -lnfc $(top_builddir)/libfreefare/libfreefare.la -lssl

mifare_desfire_info_SOURCES = mifare-desfire-info.c
mifare_desfire_info_LDADD = -lnfc $(top_builddir)/libfreefare/libfreefare.la -lssl
