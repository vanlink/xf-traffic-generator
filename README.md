# xf-traffic-generator
A network traffic generator based on dpdk and lwip.

## compile
```shell
export MBEDTLS_SDK=/usr/src/mbedtls-2.25.0
export DKFW_SDK=/usr/src/dpdk-frame-new
export LWIP_SDK=/usr/src/lwip_dpdk/src
export OPENSSL_SDK=/usr/src/openssl-1.1.1w
export EXTRA_CFLAGS=-fPIC
```
DKFW_SDK can be found here: https://github.com/vanlink/dpdk_framework

```shell
cd src
make
```

## run
```shell
cd tools
python xf-generator.py -u <id> -c <config-file>
```
