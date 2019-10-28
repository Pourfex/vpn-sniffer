FROM ubuntu:latest

RUN apt-get update && apt-get install -y \
    libtins-dev \
    gcc \
    cmake \
    build-essential \
    libpcap-dev \
    libssl-dev \
    git

RUN git clone https://github.com/ReactiveX/RxCpp rxcpp && \
    cd rxcpp && \
    mkdir build && \
    cd build && \
    cmake ../ && \
    make install

WORKDIR /usr/local/src

COPY CMakeLists.txt .
ADD src ./src/

RUN cmake .

RUN make

ENTRYPOINT ["/usr/local/src/sniffer"]