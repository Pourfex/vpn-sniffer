FROM ubuntu:latest

RUN apt-get update && apt-get install -y \
    libtins-dev \
    gcc \
    cmake \
    build-essential \
    libpcap-dev \
    libssl-dev \
    iproute2 \
    git

RUN git clone https://github.com/ReactiveX/RxCpp rxcpp && \
    cd rxcpp && \
    mkdir build && \
    cd build && \
    cmake ../ && \
    make install

RUN git clone https://github.com/jarro2783/cxxopts && \
    cd cxxopts && \
    mkdir build && \
    cd build && \
    cmake ../ && \
    make install

WORKDIR /usr/local/src

COPY CMakeLists.txt .
ADD src ./src/

RUN cmake .

RUN make

ENV INTERFACE_NAME $INTERFACE_NAME
ENV CLIENT_IP $CLIENT_IP
ENV SERVER_IP $SERVER_IP

ENTRYPOINT "/usr/local/src/sniffer" --interface-name=$INTERFACE_NAME --client-ip=$CLIENT_IP --server-ip=$SERVER_IP