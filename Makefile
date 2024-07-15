vIMAGE_VERSION ?= "latest"
DOCKER_BUILD_FLAGS ?=
SCLOUD_URL ?= https://github.com/splunk/splunk-cloud-sdk-go/releases/download/v1.11.1/scloud_v7.1.0_linux_amd64.tar.gz
ENVTYPE ?= 3idx3sh1cm
.PHONY: base splunk splunk-only

base: 
	docker build ${DOCKER_BUILD_FLAGS} --build-arg SCLOUD_URL=${SCLOUD_URL} -t base-ubuntu:${IMAGE_VERSION} ./base/ubuntu

splunk: base splunk-only

splunk-only:
	docker build ${DOCKER_BUILD_FLAGS} \
		-f common-files/Dockerfile \
		--build-arg SPLUNK_BASE_IMAGE=base-ubuntu:${IMAGE_VERSION} \
		--build-arg SPLUNK_BUILD_URL=${SPLUNK_LINUX_BUILD_URL} \
		-t livehybrid/splunk-ubuntu:${IMAGE_VERSION} .

upenv:
	SPLUNK_IMAGE=livehybrid/splunk-ubuntu:${IMAGE_VERSION} docker-compose -f ${ENVTYPE}.yaml -p awsconfigurator up -d --remove-orphans 

downenv:
	docker-compose -f ${ENVTYPE}.yaml -p awsconfigurator down
