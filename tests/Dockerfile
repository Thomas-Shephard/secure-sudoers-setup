FROM rust:latest

RUN apt-get update \
    && apt-get install -y --no-install-recommends bats bubblewrap e2fsprogs libc6-dev sudo \
    && rm -rf /var/lib/apt/lists/*

RUN rustup component add llvm-tools-preview \
    && cargo install cargo-llvm-cov --locked

WORKDIR /workspace
COPY . .

RUN chmod +x /workspace/tests/run_privileged_tests.sh

CMD ["/workspace/tests/run_privileged_tests.sh"]
