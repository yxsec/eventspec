# EventSpec reproducibility image.
#
# Pins the OS + system libraries needed by Gigahorse/Souffle, the Greed
# symbolic-execution module, and the EventSpec Python implementation in
# a single image so that reviewers can rebuild the environment with
#     docker build -t eventspec:latest .
#
# After build, verify the CLI with:
#     docker run --rm eventspec:latest python3 main.py --help
#
# Base layer (ubuntu 22.04 + Souffle 2.4 + Gigahorse + Greed) mirrors
# the upstream greed/docker/dockerfile recipe.

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    GREED_DIR=/home/greed \
    GIGAHORSE_DIR=/home/greed/gigahorse-toolchain \
    WORKDIR_APP=/work

RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-venv virtualenv git \
    gcc cmake gperf libgmp-dev bison build-essential clang \
    doxygen flex g++ libffi-dev libffi7 libncurses5-dev libsqlite3-dev \
    zlib1g-dev libboost-all-dev wget unzip mcpp sqlite genisoimage \
    curl make pkg-config nano time software-properties-common \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------
# Souffle 2.4 (pinned)
# ---------------------------------------------------------------
WORKDIR /home
RUN git clone --branch 2.4 --depth 1 https://github.com/souffle-lang/souffle \
 && cd souffle \
 && test "$(git rev-parse HEAD)" = "b60c8e9f3b9cc6b3e8b980a44fa53033328accee" \
 && cmake -S . -B build -DCMAKE_INSTALL_PREFIX=/usr \
 && cmake --build build --target install -j"$(nproc)" \
 && cd .. && rm -rf souffle

# ---------------------------------------------------------------
# Gigahorse + Greed (pulled from the upstream repos)
# ---------------------------------------------------------------
RUN git clone https://github.com/ucsb-seclab/greed.git "${GREED_DIR}" \
 && cd "${GREED_DIR}" \
 && git checkout b8de7963089861f1c1d76c881e085dacbd62abda
WORKDIR ${GREED_DIR}
RUN git clone --recursive https://github.com/nevillegrech/gigahorse-toolchain.git "${GIGAHORSE_DIR}" \
 && cd "${GIGAHORSE_DIR}" \
 && git checkout ceebabd2621a5d58d34dbbd95f047fc4f56ec157 \
 && git submodule update --init --recursive

WORKDIR ${GIGAHORSE_DIR}/souffle-addon
RUN make WORD_SIZE=$(souffle --version | sed -n 3p | cut -c12,13) -i || true

WORKDIR ${GREED_DIR}
RUN cp ${GREED_DIR}/resources/greed_client.dl ${GIGAHORSE_DIR}/clientlib/ && \
    souffle --jobs 1 -M "GIGAHORSE_DIR=${GIGAHORSE_DIR} BULK_ANALYSIS=" \
        -o ${GIGAHORSE_DIR}/clients/main.dl_compiled.tmp \
        ${GIGAHORSE_DIR}/logic/main.dl \
        -L ${GIGAHORSE_DIR}/souffle-addon && \
    mv ${GIGAHORSE_DIR}/clients/main.dl_compiled.tmp ${GIGAHORSE_DIR}/clients/main.dl_compiled && \
    mv ${GIGAHORSE_DIR}/clients/main.dl_compiled.tmp.cpp ${GIGAHORSE_DIR}/clients/main.dl_compiled.cpp && \
    souffle --jobs 1 -M "GIGAHORSE_DIR=${GIGAHORSE_DIR} BULK_ANALYSIS=" \
        -o ${GIGAHORSE_DIR}/clients/greed_client.dl_compiled.tmp \
        ${GIGAHORSE_DIR}/clientlib/greed_client.dl \
        -L ${GIGAHORSE_DIR}/souffle-addon && \
    mv ${GIGAHORSE_DIR}/clients/greed_client.dl_compiled.tmp ${GIGAHORSE_DIR}/clients/greed_client.dl_compiled && \
    mv ${GIGAHORSE_DIR}/clients/greed_client.dl_compiled.tmp.cpp ${GIGAHORSE_DIR}/clients/greed_client.dl_compiled.cpp

RUN virtualenv greed-venv && . greed-venv/bin/activate && ./setup.sh --no-gigahorse

# ---------------------------------------------------------------
# EventSpec
# ---------------------------------------------------------------
WORKDIR ${WORKDIR_APP}
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt
COPY . ${WORKDIR_APP}
# The runtime PATH points at Greed's virtualenv; install the artifact's
# pinned dependencies there as well so the executing interpreter is reproducible.
RUN ${GREED_DIR}/greed-venv/bin/pip install --no-cache-dir -r ${WORKDIR_APP}/requirements.txt

ENV PYTHONUNBUFFERED=1 \
    PATH="${GREED_DIR}/greed-venv/bin:${PATH}"

# Quick smoke test on build (optional, comment out for faster builds):
# RUN python3 main.py --help

CMD ["python3", "main.py", "--help"]
