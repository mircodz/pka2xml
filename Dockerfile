FROM ubuntu:20.04

RUN apt-get update
RUN apt-get install build-essential zlib1g-dev libcrypto++-dev libre2-dev -y

# Prepare workspace
RUN mkdir /workspace
WORKDIR /workspace
COPY . /workspace

# Install
RUN make static-install-docker

CMD ["/bin/bash"]