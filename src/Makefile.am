lib_LTLIBRARIES = libethutils.la
ethutilsdir = $(includedir)/eth-utils

libethutils_la_CXXFLAGS = \
  -I$(top_srcdir) \
  $(SECP256K1_CFLAGS) $(GLOG_CFLAGS)
libethutils_la_LIBADD = \
  $(top_builddir)/keccak/libkeccak.la \
  $(SECP256K1_LIBS) $(GLOG_LIBS)
libethutils_la_SOURCES = \
  abi.cpp \
  address.cpp \
  ecdsa.cpp \
  hexutils.cpp \
  keccak.cpp
ethutils_HEADERS = \
  abi.hpp \
  address.hpp \
  ecdsa.hpp \
  hexutils.hpp \
  keccak.hpp

check_PROGRAMS = tests
TESTS = tests

tests_CXXFLAGS = $(GLOG_CFLAGS) $(GTEST_CFLAGS)
tests_LDADD = $(builddir)/libethutils.la \
  $(GLOG_LIBS) $(GTEST_LIBS)
tests_SOURCES = \
  abi_tests.cpp \
  address_tests.cpp \
  ecdsa_tests.cpp \
  hexutils_tests.cpp \
  keccak_tests.cpp
