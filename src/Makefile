LIBS = -L${RTE_SDK}/${RTE_TARGET}/lib -Wl,--whole-archive,-ldpdk,--no-whole-archive -lrt -lm -ldl -lcrypto -pthread -lnuma -lcjson -fpic
INCLUDE = -I${RTE_SDK}/${RTE_TARGET}/include -I${DKFW_SDK}/include -I${MBEDTLS_SDK}/include -I${LWIP_SDK}/include
DEPS = -Wall -Wextra -march=native -DALLOW_EXPERIMENTAL_API
SLIBS = ${LWIP_SDK}/liblwipdpdk.a ${DKFW_SDK}/libdkfw.a ${MBEDTLS_SDK}/library/libmbedtls.a ${MBEDTLS_SDK}/library/libmbedcrypto.a ${MBEDTLS_SDK}/library/libmbedx509.a

ifeq ($(D),1)
OPTIMIZE=-O0
else
OPTIMIZE=-O2
endif

all: xf-generator

xf-generator:
	gcc -g ${OPTIMIZE} ${DEPS} ${INCLUDE} ${LIBS} xf-generator.c xf-session.c ${SLIBS} -o xf-generator

clean:
	rm -f xf-generator
