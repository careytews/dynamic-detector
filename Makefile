# More documentation is here:
# https://wiki.dev.trustnetworks.com/development/golang/go-build-system
#
# PROJSL        - project symlink; we go build here
# COMMONDIR     - common is cloned here
# COMMONVENDSL  - common symlink in the vendor folder
#
# make all         - builds everything including docker container image
# make godeps      - gets all the go build dependencies
# make build       - just runs go build, no dependency fetching
# make mostlyclean - removes anything created by this make, except dep cache
# make clean       - removes anything created by this make

ANALYTIC=dynamic-detector
VERSION=unknown
CONTAINER=gcr.io/trust-networks/analytics-${ANALYTIC}:${VERSION}

SRCDIR=go/src
PROJSL=${SRCDIR}/project
GITHUBVEND=vendor/github.com
COMMONDIR=${SRCDIR}/analytics-common
COMMONREPO=trustnetworks/analytics-common
COMMONVENDSL=${GITHUBVEND}/${COMMONREPO}
INDICATORSDIR=${SRCDIR}/indicators
INDICATORSREPO=trustnetworks/indicators
INDICATORSVENDSL=${GITHUBVEND}/${INDICATORSREPO}
LIBDIR=${SRCDIR}/detectorlib
LIBREPO=trustnetworks/detectorlib
LIBVENDSL=${GITHUBVEND}/${LIBREPO}

DEPTOOL=dep ensure -vendor-only -v
SETGOPATH=export GOPATH=$$(pwd)/go

all: godeps build container

version:
	@echo ${VERSION}

build:
	${SETGOPATH} && cd ${PROJSL} && go build -o ${ANALYTIC}

godeps: vend-common vend-indicators vend-detectorlib vend-analytic ${COMMONVENDSL} ${INDICATORSVENDSL} ${LIBVENDSL}

${PROJSL}: ${SRCDIR}
	ln -s ../.. ${PROJSL}

${SRCDIR}:
	mkdir -p ${SRCDIR}

vend-analytic: Gopkg.lock ${PROJSL}
	${SETGOPATH} && cd ${PROJSL} && ${DEPTOOL}

${COMMONVENDSL}: get-common vend-analytic
	mkdir -p ${GITHUBVEND}/trustnetworks
	ln -s ../../../${COMMONDIR} ${COMMONVENDSL}

vend-common: get-common ${COMMONDIR}/Gopkg.lock
	${SETGOPATH} && cd ${COMMONDIR} && ${DEPTOOL}

get-common: ${SRCDIR}
	@if [ -d "${COMMONDIR}" ]; then \
		cd ${COMMONDIR} && git pull; \
	else \
		cd ${SRCDIR} && git clone git@github.com:${COMMONREPO}; \
	fi

${INDICATORSVENDSL}: get-indicators vend-analytic
	mkdir -p ${GITHUBVEND}/trustnetworks
	ln -s ../../../${INDICATORSDIR} ${INDICATORSVENDSL}

vend-indicators: get-indicators ${INDICATORSDIR}/Gopkg.lock
	${SETGOPATH} && cd ${INDICATORSDIR} && ${DEPTOOL}

get-indicators: ${SRCDIR}
	@if [ -d "${INDICATORSDIR}" ]; then \
		cd ${INDICATORSDIR} && git pull; \
	else \
		cd ${SRCDIR} && git clone git@github.com:${INDICATORSREPO}; \
	fi

${LIBVENDSL}: get-detectorlib vend-analytic
	mkdir -p ${GITHUBVEND}/trustnetworks
	ln -s ../../../${LIBDIR} ${LIBVENDSL}

vend-detectorlib: get-detectorlib ${LIBDIR}/Gopkg.lock
	${SETGOPATH} && cd ${LIBDIR} && ${DEPTOOL}

get-detectorlib: ${SRCDIR}
	@if [ -d "${LIBDIR}" ]; then \
		cd ${LIBDIR} && git pull; \
	else \
		cd ${SRCDIR} && git clone git@github.com:${LIBREPO}; \
	fi

container:
	docker build -t ${CONTAINER} -f Dockerfile .

push:
	gcloud docker -- push ${CONTAINER}

mostlyclean:
	rm -f ${ANALYTIC}
	rm -rf ${SRCDIR} # leaves dep cache
	rm -rf vendor

clean: mostlyclean
	rm -rf go # clears dep cache

test:
	${SETGOPATH} && cd ${PROJSL} && go test
