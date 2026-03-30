FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# Install all build tools and dependencies that the MS cpp devcontainer
# image normally provides, plus project-specific needs (libssl-dev)
RUN apt update && apt install -y --no-install-recommends \
    build-essential \
    cmake \
    cppcheck \
    valgrind \
    clang \
    lldb \
    llvm \
    gdb \
    git \
    curl \
    wget \
    sudo \
    openssh-client \
    libssl-dev \
    pkg-config \
    zip \
    unzip \
    tar \
    ca-certificates \
    locales \
    lsof \
    net-tools \
    procps \
    man-db \
    less \
    libncurses-dev \
    powershell \
    && rm -rf /var/lib/apt/lists/*

# Generate en_US.UTF-8 locale (Kali minimal image lacks it)
RUN sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen && locale-gen
ENV LANG=en_US.UTF-8

# Create the vscode user with passwordless sudo (Kali defaults to root)
RUN groupadd --gid 1000 vscode \
    && useradd -s /bin/bash --uid 1000 --gid 1000 -m vscode \
    && echo "vscode ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/vscode \
    && chmod 0440 /etc/sudoers.d/vscode
