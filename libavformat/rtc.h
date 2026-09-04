/*
 * Shared WebRTC helpers
 * Copyright (c) 2026 The FFmpeg Project
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef AVFORMAT_RTC_H
#define AVFORMAT_RTC_H

#include <stdint.h>
#include <stddef.h>

#include "libavutil/lfg.h"

#include "avformat.h"
#include "tls.h"
#include "url.h"

/**
 * Maximum size limit of a Session Description Protocol (SDP),
 * be it an offer or answer.
 */
#define RTC_MAX_SDP_SIZE 8192

#define RTC_US_PER_MS 1000

/**
 * If we try to read from UDP and get EAGAIN, we sleep for 5ms and retry up to 10 times.
 * This will limit the total duration (in milliseconds, 50ms)
 */
#define RTC_ICE_DTLS_READ_MAX_RETRY 10
#define RTC_ICE_DTLS_READ_SLEEP_DURATION 5

/**
 * Maximum size of the buffer for sending and receiving UDP packets.
 * Please note that this size does not limit the size of the UDP packet that can be sent.
 * To set the limit for packet size, modify the `pkt_size` parameter.
 * For instance, it is possible to set the UDP buffer to 4096 to send or receive packets,
 * but please keep in mind that the `pkt_size` option limits the packet size to 1400.
 */
#define RTC_MAX_UDP_BUFFER_SIZE 4096

#define RTC_ICE_UFRAG_SIZE 9
#define RTC_ICE_PWD_SIZE 33

/**
 * The size of the Secure Real-time Transport Protocol (SRTP) master key material
 * that is exported by Secure Sockets Layer (SSL) after a successful Datagram
 * Transport Layer Security (DTLS) handshake. This material consists of a key
 * of 16 bytes and a salt of 14 bytes.
 */
#define RTC_DTLS_SRTP_KEY_LEN 16
#define RTC_DTLS_SRTP_SALT_LEN 14

/**
 * The maximum size of the Secure Real-time Transport Protocol (SRTP) HMAC checksum
 * and padding that is appended to the end of the packet. To calculate the maximum
 * size of the User Datagram Protocol (UDP) packet that can be sent out, subtract
 * this size from the `pkt_size`.
 */
#define RTC_DTLS_SRTP_CHECKSUM_LEN 16

/**
 * The maximum size of the PEM certificate and private key buffers
 * used by the DTLS handshake.
 */
#define RTC_MAX_CERTIFICATE_SIZE 8192

/**
 * The STUN message header, which is 20 bytes long, comprises the
 * STUNMessageType (1B), MessageLength (2B), MagicCookie (4B),
 * and TransactionID (12B).
 * See https://datatracker.ietf.org/doc/html/rfc5389#section-6
 */
#define RTC_STUN_HEADER_SIZE 20

/**
 * The RTP header is 12 bytes long, comprising the Version(1B), PT(1B),
 * SequenceNumber(2B), Timestamp(4B), and SSRC(4B).
 * See https://www.rfc-editor.org/rfc/rfc3550#section-5.1
 */
#define RTC_RTP_HEADER_SIZE 12

/**
 * For RTCP, PT is [128, 223] (or without marker [0, 95]). Literally, RTCP starts
 * from 64 not 0, so PT is [192, 223] (or without marker [64, 95]), see "RTCP Control
 * Packet Types (PT)" at
 * https://www.iana.org/assignments/rtp-parameters/rtp-parameters.xhtml#rtp-parameters-4
 *
 * For RTP, the PT is [96, 127], or [224, 255] with marker. See "RTP Payload Types (PT)
 * for standard audio and video encodings" at
 * https://www.iana.org/assignments/rtp-parameters/rtp-parameters.xhtml#rtp-parameters-1
 */
#define RTC_RTCP_PT_START 192
#define RTC_RTCP_PT_END   223

/* Calculate the elapsed time from starttime to endtime in milliseconds. */
#define RTC_ELAPSED(starttime, endtime) ((float)(endtime - starttime) / 1000)

enum RTCState {
    RTC_STATE_NONE,

    /* The initial state. */
    RTC_STATE_INITIALIZED,
    /* The muxer has sent the offer to the peer. */
    RTC_STATE_LOCAL_SDP_READY,
    /* The muxer has received the answer from the peer. */
    RTC_STATE_REMOTE_SDP_RECEIVED,
    /**
     * After parsing the answer received from the peer, the muxer negotiates the abilities
     * in the offer that it generated.
     */
    RTC_STATE_NEGOTIATED,
    /* The muxer has connected to the peer via UDP. */
    RTC_STATE_UDP_CONNECTED,
    /* The muxer has sent the ICE request to the peer. */
    RTC_STATE_ICE_CONNECTING,
    /* The muxer has received the ICE response from the peer. */
    RTC_STATE_ICE_CONNECTED,
    /* The muxer has finished the DTLS handshake with the peer. */
    RTC_STATE_DTLS_CONNECTED,
    /* The muxer has finished the SRTP setup. */
    RTC_STATE_SRTP_READY,
    /* The muxer is ready to send/receive media frames. */
    RTC_STATE_READY,
    /* The muxer is failed. */
    RTC_STATE_FAILED,
};

typedef enum RTCFlags {
    RTC_DTLS_ACTIVE = (1 << 0),
} RTCFlags;

typedef struct RTCContext {
    AVFormatContext *ctx;

    /* The state of the RTC connection. */
    enum RTCState state;
    uint32_t flags;

    /* The timeout in milliseconds for ICE and DTLS handshake. */
    int handshake_timeout;
    /* The timeout in microseconds for HTTP operations. */
    int64_t timeout;
    /**
     * The size of RTP packet, should generally be set to MTU.
     * Note that pion requires a smaller value, for example, 1200.
     */
    int pkt_size;
    int buffer_size; /* Underlying protocol send/receive buffer size */

    /* The random number generator. */
    AVLFG rnd;

    /* The ICE username and pwd fragment generated by the muxer. */
    char ice_ufrag_local[RTC_ICE_UFRAG_SIZE];
    char ice_pwd_local[RTC_ICE_PWD_SIZE];

    int is_peer_ice_lite;
    uint64_t ice_tie_breaker; // random 64 bit, for ICE-CONTROLLING
    /* The ICE username and pwd from remote server. */
    char *ice_ufrag_remote;
    char *ice_pwd_remote;
    /**
     * This represents the ICE candidate protocol, priority, host and port.
     * Currently, we only support one candidate and choose the first UDP candidate.
     * However, we plan to support multiple candidates in the future.
     */
    char *ice_protocol;
    char *ice_host;
    int ice_port;

    /**
     * This is the SDP offer generated by the muxer based on the codec parameters,
     * DTLS, and ICE information.
     */
    char *local_sdp;
    /* The SDP answer received from the WebRTC server. */
    char *remote_sdp;
    /**
     * The optional Bearer token for HTTP Authorization.
     * See https://www.ietf.org/archive/id/draft-ietf-wish-whip-08.html#name-authentication-and-authoriz
     */
    char *authorization;

    /* The certificate and private key used for DTLS handshake. */
    char *cert_file;
    char *key_file;
    /* The certificate and private key content used for DTLS handshake */
    char cert_buf[RTC_MAX_CERTIFICATE_SIZE];
    char key_buf[RTC_MAX_CERTIFICATE_SIZE];
    /* The fingerprint of certificate, used in SDP offer. */
    char *local_fingerprint;
    /* remote DTLS cert fingerprint from SDP answer (sha-256). */
    char *remote_fingerprint;

    /* The UDP transport is used for delivering ICE, DTLS and SRTP packets. */
    URLContext *udp;
    /* TODO: Use AVIOContext instead of URLContext */
    URLContext *dtls;

    /**
     * This represents the material used to build the SRTP master key. It is
     * generated by DTLS and has the following layout:
     *          16B         16B         14B             14B
     *      client_key | server_key | client_salt | server_salt
     */
    uint8_t dtls_srtp_materials[(RTC_DTLS_SRTP_KEY_LEN + RTC_DTLS_SRTP_SALT_LEN) * 2];
    /* The buffer for UDP transmission. */
    char buf[RTC_MAX_UDP_BUFFER_SIZE];

    /* These variables represent timestamps used for calculating and tracking the cost. */
    int64_t start_time;
    int64_t init_time;
    int64_t offer_time;
    int64_t answer_time;
    int64_t udp_time;
    int64_t ice_time;
    int64_t dtls_time;
    int64_t srtp_time;
    int64_t last_consent_tx_time;
    int64_t last_consent_rx_time;
} RTCContext;

int ff_rtc_ice_create_binding_request(RTCContext *rtc,
                                      uint8_t *buf, int buf_size,
                                      int *request_size);
int ff_rtc_ice_create_binding_response(RTCContext *rtc,
                                       char *tid, int tid_size,
                                       uint8_t *buf, int buf_size,
                                       int *response_size);
int ff_rtc_ice_is_binding_request(uint8_t *b, int size);
int ff_rtc_ice_is_binding_response(uint8_t *b, int size);

int ff_rtc_is_rtp_or_rtcp(const uint8_t *b, int size);
int ff_rtc_is_rtcp(const uint8_t *b, int size);

int ff_rtc_init_certificate(RTCContext *rtc);
int ff_rtc_dtls_open(RTCContext *rtc);
int ff_rtc_session_init(RTCContext *rtc);
int ff_rtc_parse_answer(RTCContext *rtc);
int ff_rtc_udp_connect(RTCContext *rtc);
int ff_rtc_ice_handle_binding_request(RTCContext *rtc, char *buf, int buf_size);
int ff_rtc_ice_dtls_handshake(RTCContext *rtc);
int ff_rtc_dtls_export_materials(RTCContext *rtc, char *send_key, char *recv_key);
void ff_rtc_session_deinit(RTCContext *rtc);
#endif /* AVFORMAT_RTC_H */
