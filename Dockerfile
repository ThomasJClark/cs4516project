FROM golang:1.5

RUN apt-get update && apt-get install -y net-tools iptables libnetfilter-queue-dev
RUN mkdir -p /go/src/github.com/ThomasJClark/cs4516project
WORKDIR /go/src/github.com/ThomasJClark/cs4516project
COPY . /go/src/github.com/ThomasJClark/cs4516project

RUN go get . && go install .
