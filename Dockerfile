FROM ubuntu:latest

WORKDIR /usr/local

COPY CMakeLists.txt src /usr/local/

RUN apt-get update && apt-get install -y \
    libtins-dev \
    gcc \
    cmake \
    build-essential \
    libpcap-dev \
    libssl-dev

RUN cmake .

RUN make

ENTRYPOINT sniffer