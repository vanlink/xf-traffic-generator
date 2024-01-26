LLHTTP_DIR=llhttp

PKGCONF=pkg-config

LIBS = $(shell $(PKGCONF) --libs libdpdk) -lrt -lm -ldl -lcrypto -pthread -lnuma -lcjson -lpcap ${MBEDTLS_SDK}/library/libmbedtls.a ${MBEDTLS_SDK}/library/libmbedcrypto.a ${MBEDTLS_SDK}/library/libmbedx509.a -fpic
INCLUDE = -I${DKFW_SDK}/include -I${MBEDTLS_SDK}/include -I${LWIP_SDK}/include -I${LLHTTP_DIR}/include
DEPS = -Wall -Wextra $(shell $(PKGCONF) --cflags libdpdk) -march=native -DALLOW_EXPERIMENTAL_API
SLIBS = ${LWIP_SDK}/liblwipdpdk.a ${DKFW_SDK}/libdkfw.a \
        ${LLHTTP_DIR}/libllhttp.a

ifeq ($(D),1)
OPTIMIZE=-O0
else
OPTIMIZE=-O2
endif

SRC=xf-generator.c xf-session.c xf-stream.c xf-tools.c xf-network.c xf-address.c \
    xf-protocol-http-msg.c xf-protocol-http.c xf-protocol-common.c xf-capture.c \
    xf-simuser.c xf-certificate.c

all: xf-generator-main xf-generator-control xf-generator-daemon

xf-generator-main:
	gcc -g ${OPTIMIZE} ${DEPS} ${INCLUDE} ${SRC} ${SLIBS} ${LIBS} -o xf-generator-main

xf-generator-control:
	gcc -g ${OPTIMIZE} ${DEPS} ${INCLUDE} xf-generator-control.c ${SLIBS} ${LIBS} -o xf-generator-control

xf-generator-daemon:
	gcc -g ${OPTIMIZE} ${DEPS} ${INCLUDE} xf-generator-daemon.c ${SLIBS} ${LIBS} -o xf-generator-daemon

clean:
	rm -f xf-generator-main xf-generator-control xf-generator-daemon
