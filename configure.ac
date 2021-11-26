AC_INIT([eth-utils], [0.1])
AM_INIT_AUTOMAKE([subdir-objects])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AM_SILENT_RULES([yes])

AC_PROG_CXX
AM_PROG_AR
PKG_INSTALLDIR

AC_LANG([C++])
LT_INIT

AX_CXX_COMPILE_STDCXX([14], [noext])
AX_CHECK_COMPILE_FLAG([-Wall], [CXXFLAGS="${CXXFLAGS} -Wall"])
AX_CHECK_COMPILE_FLAG([-Werror], [CXXFLAGS="${CXXFLAGS} -Werror"])
AX_CHECK_COMPILE_FLAG([-pedantic], [CXXFLAGS="${CXXFLAGS} -pedantic"])
AX_CHECK_COMPILE_FLAG([-Wno-deprecated],
                      [CXXFLAGS="${CXXFLAGS} -Wno-deprecated"])

# Windows defines ERROR, which requires us to tell glog to not define
# it as abbreviated log severity (LOG(ERROR) still works, though, and
# that is all that we actually use in the code).
# See https://hpc.nih.gov/development/glog.html.
CXXFLAGS="${CXXFLAGS} -DGLOG_NO_ABBREVIATED_SEVERITIES"

# Private dependencies of the library itself.
AX_PKG_CHECK_MODULES([SECP256K1], [], [libglog])
AX_PKG_CHECK_MODULES([GLOG], [], [libsecp256k1])

# Private dependencies that are not needed for the library, but only for
# the unit tests.
PKG_CHECK_MODULES([GTEST], [gtest_main])

AC_CONFIG_FILES([
  Makefile \
  keccak/Makefile \
  src/Makefile \
  \
  ethutils.pc
])
AC_OUTPUT

echo
echo "CXXFLAGS: ${CXXFLAGS}"
