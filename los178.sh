#!/bin/sh
# Build dropbear. It will be included in the bsp.

if ! [ -e configure ] ; then
  autoconf
  autoheader
fi

CPPFLAGS="-DVMOS_DEV -D__NO_INCLUDE_WARN__" \
LDFLAGS="-Wl,--start-group -lbsd -ltrio" \
./configure --host=x86 --disable-lastlog --disable-utmp --disable-utmpx --disable-wtmp --disable-wtmpx --disable-syslog --enable-bundled-libtom --prefix=/bin

# Build dropbear and scp
lwsmgr
make clean
make PROGRAMS="dropbear dbclient scp dropbearkey" MULTI=1 STATIC=1 SCPPROGRESS=1
lwsmgr -s
DEST=$ENV_PREFIX/bin
#[ -d "$DEST" ] || mkdir -p $DEST

cp dropbearmulti dropbearmulti.stripped
strip dropbearmulti.stripped
cp dropbearmulti.stripped $DEST/dropbearmulti
echo "Updated: $DEST/dropbearmulti"
