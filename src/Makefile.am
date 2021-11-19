lib_LTLIBRARIES = libethutils.la
ethutilsdir = $(includedir)/eth-utils

libethutils_la_CXXFLAGS = \
  -I$(top_srcdir) \
  $(GLOG_CFLAGS)
libethutils_la_LIBADD = \
  $(top_builddir)/keccak/libkeccak.la \
  $(GLOG_LIBS)
libethutils_la_SOURCES = \
  hexutils.cpp \
  keccak.cpp
ethutils_HEADERS = \
  hexutils.hpp \
  keccak.hpp

check_PROGRAMS = tests
TESTS = tests

tests_CXXFLAGS = $(GLOG_CFLAGS) $(GTEST_CFLAGS)
tests_LDADD = $(builddir)/libethutils.la \
  $(GLOG_LIBS) $(GTEST_LIBS)
tests_SOURCES = \
  hexutils_tests.cpp \
  keccak_tests.cpp
