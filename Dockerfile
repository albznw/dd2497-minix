FROM debian/eol:jessie-slim

# Install dependencies
RUN apt-get update  \
    && apt-get install -y \
    build-essential \
    curl            \
    git             \
    zlibc           \
    zlib1g          \
    zlib1g-dev      \ 
    g++             \
    && mkdir /workspace

WORKDIR /workspace