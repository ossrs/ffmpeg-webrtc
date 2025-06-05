# docker build -t ossrs/srs:ffmpeg-fate
# docker push ossrs/srs:ffmpeg-fate
FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y build-essential git rsync make nasm pkg-config libssl-dev &&\
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt
RUN git clone https://git.ffmpeg.org/ffmpeg.git ffmpeg

WORKDIR /opt/ffmpeg
RUN ./configure --enable-openssl --enable-version3
RUN make -j$(nproc)

RUN make fate-rsync SAMPLES=/opt/ffmpeg/fate-suite
RUN du -sh /opt/ffmpeg/fate-suite

# Note that you should use the fate-suite.tar, then extract it out of 
# docker, to avoid resync all files.
RUN tar cf fate-suite.tar fate-suite 
RUN du -sh /opt/ffmpeg/fate-suite.tar

ENV FATE_SAMPLES=/opt/ffmpeg/fate-suite
