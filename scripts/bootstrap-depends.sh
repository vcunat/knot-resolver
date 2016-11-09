#!/bin/bash -x
#set -e

SCRIPT_DIR=$(dirname $(pwd)/${0})

CMOCKA_TAG="cmocka-1.1.0"
CMOCKA_URL="git://git.cryptomilk.org/projects/cmocka.git"
LIBUV_TAG="v1.x"
LIBUV_URL="https://github.com/libuv/libuv.git"
KNOT_TAG="v2.3.1"
KNOT_URL="https://github.com/CZ-NIC/knot.git"
GMP_TAG="6.1.1"
GMP_URL="https://gmplib.org/download/gmp/gmp-${GMP_TAG}.tar.xz"
JANSSON_TAG="2.9"
JANSSON_URL="http://www.digip.org/jansson/releases/jansson-${JANSSON_TAG}.tar.gz"
NETTLE_TAG="3.3"
NETTLE_URL="https://ftp.gnu.org/gnu/nettle/nettle-${NETTLE_TAG}.tar.gz"
GNUTLS_TAG="3.5.5"
GNUTLS_URL="ftp://ftp.gnutls.org/gcrypt/gnutls/v3.5/gnutls-${GNUTLS_TAG}.tar.xz"
LUA_TAG="v2.1.0-beta2"
LUA_URL="https://github.com/LuaJIT/LuaJIT.git"
HIREDIS_TAG="v0.13.3"
HIREDIS_URL="https://github.com/redis/hiredis.git"
LIBMEMCACHED_TAG="1.0.18"
LIBMEMCACHED_URL="https://launchpad.net/libmemcached/1.0/1.0.18/+download/libmemcached-1.0.18.tar.gz"

# prepare install prefix
PREFIX=${1}; [ -z ${PREFIX} ] && export PREFIX="${HOME}/.local"

function bootstrap_cleanup {
    if [ -n "$BOOTSTRAP_CLEANUP" ]; then
	echo "Bootstrap script has changed, cleaning up ${PREFIX}"
	rm -rf "${PREFIX}"
    else
	echo "Bootstrap script has changed, you should cleanup ${PREFIX}"
	echo "or rerun this script with BOOSTRAP_CLEANUP=1 env variable"
    fi
}

if [ -f ${PREFIX}/.revision ]; then
    cd ${SCRIPT_DIR}
    if ! shasum -a 256 -c ${PREFIX}/.revision >/dev/null 2>/dev/null; then
	# bootstrap script has changed, do a clean rebuild
	bootstrap_cleanup
    fi
else
    # failed build, etc...
    if [ -d "${PREFIX}/" ]; then
	bootstrap_cleanup
    fi
fi

install -d ${PREFIX}/{lib,libexec,include,bin,sbin,man,share,etc,info,doc,var}

# prepare build env
export PKG_CONFIG_PATH="${PREFIX}/lib/pkgconfig:${PKG_CONFIG_PATH}"
export BUILD_DIR="$(pwd)/.build-depend"
export LOG=$(pwd)/build.log
[ ! -e ${BUILD_DIR} ] && mkdir ${BUILD_DIR}; cd ${BUILD_DIR}
echo "build: ${BUILD_DIR}"
echo "log:   ${LOG}" | tee ${LOG}

function on_failure {
	cat ${LOG}
}
trap on_failure ERR

function fetch_pkg {
	if [ "${2##*.}" == git ]; then
		[ ! -e $1 ] && git clone "$2" $1 &> /dev/null
		cd $1; git checkout $3 &> /dev/null; cd -
	else
		[ ! -f $1.tar.${2##*.} ] && curl -L "$2" > $1.tar.${2##*.}
		tar xf $1.tar.${2##*.}
	fi
	cd $1
}

function build_pkg {
	if [ -f configure.ac ]; then
		if [ ! -e ./configure ]; then
			[ -e autogen.sh ] && sh autogen.sh || autoreconf -if
		fi
		./configure --prefix=${PREFIX} --enable-shared $*
		make ${MAKEOPTS}
		make install
	elif [ -f CMakeLists.txt ]; then
		[ -e cmake-build ] && rm -rf cmake-build; mkdir cmake-build; cd cmake-build
		cmake -DCMAKE_INSTALL_PREFIX=${PREFIX} ..
		make ${MAKEOPTS}
		make install
	else
		make $*
	fi
}

function pkg {
	if [ ! -e ${PREFIX}/$4 ] && [ "${BUILD_IGNORE}" == "${BUILD_IGNORE/$1/}" ] ; then
		cd ${BUILD_DIR}
		echo "[x] fetching $1-$3"
		fetch_pkg "$1-$3" "$2" $3 >> ${LOG}
		echo "[x] building $1-$3"
		shift 4
		(build_pkg $*) >> ${LOG} 2>&1
	fi
}

# travis-specific
PIP_PKGS="dnspython==1.11 cpp-coveralls Jinja2"
if [ "${TRAVIS_OS_NAME}" == "osx" ]; then
	brew update
	brew install --force makedepend python hiredis libmemcached || true
	brew link --overwrite python || true
	pip install --upgrade pip || true
	pip install ${PIP_PKGS}
fi
if [ "${TRAVIS_OS_NAME}" == "linux" ]; then
	pip install --user ${USER} --upgrade pip || true
	pip install --user ${USER} ${PIP_PKGS} || true
	rm ${HOME}/.cache/pip/log/debug.log || true
	pkg hiredis ${HIREDIS_URL} ${HIREDIS_TAG} include/hiredis/hiredis.h install PREFIX=${PREFIX}
	pkg libmemcached ${LIBMEMCACHED_URL} ${LIBMEMCACHED_TAG} include/libmemcached/memcached.h
fi

pkg gmp ${GMP_URL} ${GMP_TAG} include/gmp.h --disable-static
pkg nettle ${NETTLE_URL} ${NETTLE_TAG} include/nettle \
	--disable-documentation --with-lib-path=${PREFIX}/lib --with-include-path=${PREFIX}/include
export GMP_CFLAGS="-I${PREFIX}/include"
export GMP_LIBS="-L${PREFIX}/lib -lgmp"
pkg gnutls ${GNUTLS_URL} ${GNUTLS_TAG} include/gnutls \
    --disable-tests --disable-doc --disable-valgrind-tests --disable-static --with-included-libtasn1 --without-p11-kit \
    --disable-tools --disable-cxx
pkg jansson ${JANSSON_URL} ${JANSSON_TAG} include/jansson.h --disable-static
pkg libknot ${KNOT_URL} ${KNOT_TAG} include/libknot \
	--disable-static --with-lmdb=no --disable-fastparser --disable-daemon --disable-utilities --disable-documentation
pkg cmocka ${CMOCKA_URL} ${CMOCKA_TAG} include/cmocka.h
pkg libuv ${LIBUV_URL} ${LIBUV_TAG} include/uv.h --disable-static
pkg lua ${LUA_URL} ${LUA_TAG} lib/pkgconfig/luajit.pc install BUILDMODE=dynamic LDFLAGS=-lm PREFIX=${PREFIX}

echo "Build success!"

# remove on successful build
rm -rf ${BUILD_DIR}

cd ${SCRIPT_DIR}
shasum -a 256 $(basename $0) > ${PREFIX}/.revision

exit 0
