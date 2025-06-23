# darwin-arm64 virtualization settings for docker deamon:
# colima start <my-x86-vm> --arch x86_64 --vm-type qemu --memory 4 --disk 60

# build and run libdft image:
# docker build --platform linux/amd64 -t libdft-image:latest .
# docker run -it --rm -v "$(realpath ./):/libdft" --cap-add=SYS_PTRACE --name libdft-dev libdft-image:latest

ARG BUILD_PLATFORM=linux/amd64
FROM --platform=${BUILD_PLATFORM} ubuntu:20.04

RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get -y upgrade && \
    DEBIAN_FRONTEND="noninteractive" apt-get -y install --no-install-recommends \
        ca-certificates \
        build-essential \
        gcc-multilib \
        g++-multilib \
        gdb \
        git \
        vim \
        file \
        python3 \
        python3-pip \
        clang \
        libclang-dev \
        wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# pin tool
ENV PIN_TAR_NAME="pin-3.20-98437-gf02b61307-gcc-linux"
ENV PIN_INSTALL_DIR="/opt/pin"
ENV PIN_ROOT="${PIN_INSTALL_DIR}/${PIN_TAR_NAME}"

# install pin tool
RUN mkdir -p ${PIN_INSTALL_DIR} && \
    echo "* Downloading pin tool: ${PIN_TAR_NAME}.tar.gz" && \
    wget -O /tmp/${PIN_TAR_NAME}.tar.gz "https://software.intel.com/sites/landingpage/pintool/downloads/${PIN_TAR_NAME}.tar.gz" && \
    echo "* Extracting pin tool to ${PIN_INSTALL_DIR}" && \
    tar xzf /tmp/${PIN_TAR_NAME}.tar.gz -C ${PIN_INSTALL_DIR} && \
    rm /tmp/${PIN_TAR_NAME}.tar.gz && \
    echo "* Pin tool installed at ${PIN_ROOT}"

# install compiledb
RUN echo "* Installing compiledb via pip" && \
    pip3 install compiledb && \
    pip3 install clang==10.0.1 && \
    echo "* compiledb installed successfully."

# add libclang to path
RUN ln -s /usr/lib/x86_64-linux-gnu/libclang-10.so.1 /usr/lib/x86_64-linux-gnu/libclang.so

# export pin path
ENV PATH="${PIN_ROOT}:${PATH}"

RUN mkdir -p /libdft
WORKDIR /libdft

COPY ./env.init /opt/

ENTRYPOINT [ "/opt/env.init" ]
CMD ["/bin/bash"]
# CMD ["sleep", "infinity"]
