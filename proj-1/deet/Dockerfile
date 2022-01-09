FROM ubuntu:18.04

RUN apt-get update && \
    apt-get install -y build-essential make curl strace gdb ssh \
                                                                  gcc \
                                                                  g++ \
                                                                  clang \
                                                                  ninja-build \
                                                                  cmake \
                                                                  autoconf \
                                                                  automake \
                                                                  locales-all \
                                                                  dos2unix \
                                                                  rsync \
                                                                  tar \
                                                                  python \
    && apt-get clean

# Install Rust. Don't use rustup, so we can install for all users (not just the
# root user)
RUN curl --proto '=https' --tlsv1.2 -sSf \
        https://static.rust-lang.org/dist/rust-nightly-x86_64-unknown-linux-gnu.tar.gz \
        -o rust.tar.gz && \
    tar -xzf rust.tar.gz && \
    rust-nightly-x86_64-unknown-linux-gnu/install.sh

# Make .cargo writable by any user (so we can run the container as an
# unprivileged user)
RUN mkdir /.cargo && chmod 777 /.cargo

WORKDIR /deet

RUN ( \
    echo 'LogLevel DEBUG2'; \
    echo 'PermitRootLogin yes'; \
    echo 'PasswordAuthentication yes'; \
    echo 'Subsystem sftp /usr/lib/openssh/sftp-server'; \
  ) > /etc/ssh/sshd_config_test_clion \
  && mkdir /run/sshd

RUN useradd -m user \
  && yes password | passwd user

RUN usermod -s /bin/bash user

CMD ["/usr/sbin/sshd", "-D", "-e", "-f", "/etc/ssh/sshd_config_test_clion"]