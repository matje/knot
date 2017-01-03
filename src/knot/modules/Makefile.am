LT_INIT = dlopen shared

KNOTLIBS = ../../libknotd.la ../../libcontrib.la

modulesdir = $(libdir)/knot/modules

modules_LTLIBRARIES =				\
	dnsproxy.la				\
	noudp.la				\
	online_sign.la				\
	synth_record.la				\
	whoami.la

dnsproxy_la_SOURCES = 				\
	dnsproxy/dnsproxy.c			\
	dnsproxy/dnsproxy.h
dnsproxy_la_LIBADD = $(KNOTLIBS)
dnsproxy_la_LDFLAGS = -module -avoid-version -shared

noudp_la_SOURCES = 				\
	noudp/noudp.c				\
	noudp/noudp.h
noudp_la_LIBADD = $(KNOTLIBS)
noudp_la_LDFLAGS = -module -avoid-version -shared

online_sign_la_SOURCES = 			\
	online_sign/online_sign.c		\
	online_sign/online_sign.h		\
	online_sign/nsec_next.c			\
	online_sign/nsec_next.h
online_sign_la_LIBADD = $(KNOTLIBS)
online_sign_la_LDFLAGS = -module -avoid-version -shared

synth_record_la_SOURCES = 			\
	synth_record/synth_record.c		\
	synth_record/synth_record.h
synth_record_la_LIBADD = $(KNOTLIBS)
synth_record_la_LDFLAGS = -module -avoid-version -shared

whoami_la_SOURCES = 				\
	whoami/whoami.c				\
	whoami/whoami.h
whoami_la_LIBADD = $(KNOTLIBS)
whoami_la_LDFLAGS = -module -avoid-version -shared

####################################
# Optional Knot DNS Daemon modules #
####################################

if HAVE_DNSTAP
modules_LTLIBRARIES += dnstap.la
dnstap_la_SOURCES =				\
	dnstap/dnstap.c				\
	dnstap/dnstap.h
dnstap_la_CPPFLAGS =$(DNSTAP_CFLAGS)
dnstap_la_LIBADD = $(KNOTLIBS) $(DNSTAP_LIBS) ../../contrib/dnstap/libdnstap.la
dnstap_la_LDFLAGS = -module -avoid-version -shared
endif # HAVE_DNSTAP

if HAVE_ROSEDB
modules_LTLIBRARIES += rosedb.la
rosedb_la_SOURCES =				\
	rosedb/rosedb.c				\
	rosedb/rosedb.h
rosedb_la_LIBADD = $(KNOTLIBS)
rosedb_la_LDFLAGS = -module -avoid-version -shared
endif # HAVE_ROSEDB
