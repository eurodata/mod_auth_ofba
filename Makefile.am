AUTOMAKE_OPTIONS = foreign

sbin_PROGRAMS = ofba_session
ofba_session_SOURCES = ofba_session.c auth_ofba.h
ofba_session_CFLAGS = @APR_CFLAGS@ @APRUTIL_CFLAGS@
ofba_session_LDFLAGS = @APR_LIBS@ @APRUTIL_LIBS@

EXTRA_DIST=mod_auth_ofba.c README

#   the default target
all: module ofba_session

#   compile the DSO file
module: mod_auth_ofba.c auth_ofba.h $(TARGET)
	$(APXS) -c $(LDFLAGS) $(LIBS) $(APXS_LDFLAGS) mod_auth_ofba.c

install-exec-local: module
	$(APXS) -i -a -n auth_ofba .libs/mod_auth_ofba.so

CLEANFILES=	 *.la *.lo *.o *.so *.slo .libs/*


