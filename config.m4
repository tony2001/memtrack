dnl $Id: config.m4 274405 2009-01-23 17:53:42Z tony2001 $

PHP_ARG_ENABLE(memtrack, whether to enable memtrack support,
[  --enable-memtrack           Enable memtrack support])


AC_MSG_CHECKING([whether struct mallinfo is present])
 AC_TRY_COMPILE([#include <malloc.h>], [struct mallinfo info;],
 [
  AC_MSG_RESULT([yes])
  AC_DEFINE(PHP_MEMTRACK_HAVE_MALLINFO, 1, [Whether struct mallinfo is present])
 ], [
  AC_MSG_RESULT([no])
 ])

if test "$PHP_MEMTRACK" != "no"; then
  PHP_NEW_EXTENSION(memtrack, memtrack.c, $ext_shared)
fi
