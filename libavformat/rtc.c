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

#include "libavutil/attributes_internal.h"
#include "libavutil/crc.h"
#include "libavutil/hmac.h"
#include "libavutil/intreadwrite.h"
#include "libavutil/avstring.h"
#include "libavutil/mem.h"
#include "libavutil/random_seed.h"
#include "libavutil/time.h"

#include "avio_internal.h"
#include "internal.h"
#include "network.h"
#include "rtc.h"
#include "tls.h"

/* The magic cookie for Session Traversal Utilities for NAT (STUN) messages. */
#define STUN_MAGIC_COOKIE 0x2112A442

/**
 * Refer to RFC 8445 5.1.2
 * priority = (2^24)*(type preference) + (2^8)*(local preference) + (2^0)*(256 - component ID)
 * host candidate priority is 126 << 24 | 65535 << 8 | 255
 */
#define STUN_HOST_CANDIDATE_PRIORITY 126 << 24 | 65535 << 8 | 255

/* STUN Attribute, comprehension-required range (0x0000-0x7FFF) */
enum STUNAttr {
    STUN_ATTR_USERNAME          = 0x0006,
    STUN_ATTR_PRIORITY          = 0x0024,
    STUN_ATTR_USE_CANDIDATE     = 0x0025,
    STUN_ATTR_MESSAGE_INTEGRITY = 0x0008,
    STUN_ATTR_FINGERPRINT       = 0x8028,
    STUN_ATTR_ICE_CONTROLLING   = 0x802A,
};

/**
 * Creates and marshals an ICE binding request packet.
 *
 * This function creates and marshals an ICE binding request packet. The function only
 * generates the username attribute and does not include goog-network-info,
 * use-candidate. However, some of these attributes may be added in the future.
 *
 * @param s Pointer to the AVFormatContext
 * @param buf Pointer to memory buffer to store the request packet
 * @param buf_size Size of the memory buffer
 * @param request_size Pointer to an integer that receives the size of the request packet
 * @return Returns 0 if successful or AVERROR_xxx if an error occurs.
 */
int ff_rtc_ice_create_binding_request(RTCContext *rtc,
                                      uint8_t *buf, int buf_size,
                                      int *request_size)
{
    int ret, size, crc32;
    char username[128];
    AVIOContext *pb = NULL;
    AVHMAC *hmac = NULL;

    pb = avio_alloc_context(buf, buf_size, 1, NULL, NULL, NULL, NULL);
    if (!pb)
        return AVERROR(ENOMEM);

    hmac = av_hmac_alloc(AV_HMAC_SHA1);
    if (!hmac) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

    /* Write 20 bytes header */
    avio_wb16(pb, 0x0001); /* STUN binding request */
    avio_wb16(pb, 0);      /* length */
    avio_wb32(pb, STUN_MAGIC_COOKIE); /* magic cookie */
    avio_wb32(pb, av_lfg_get(&rtc->rnd)); /* transaction ID */
    avio_wb32(pb, av_lfg_get(&rtc->rnd)); /* transaction ID */
    avio_wb32(pb, av_lfg_get(&rtc->rnd)); /* transaction ID */

    /* The username is the concatenation of the two ICE ufrag */
    ret = snprintf(username, sizeof(username), "%s:%s", rtc->ice_ufrag_remote, rtc->ice_ufrag_local);
    if (ret <= 0 || ret >= sizeof(username)) {
        av_log(rtc->ctx->priv_data, AV_LOG_ERROR, "Failed to build username %s:%s, max=%zu, ret=%d\n",
            rtc->ice_ufrag_remote, rtc->ice_ufrag_local, sizeof(username), ret);
        ret = AVERROR(EIO);
        goto end;
    }

    /* Write the username attribute */
    avio_wb16(pb, STUN_ATTR_USERNAME); /* attribute type username */
    avio_wb16(pb, ret); /* size of username */
    avio_write(pb, username, ret); /* bytes of username */
    ffio_fill(pb, 0, (4 - (ret % 4)) % 4); /* padding */

    /* Write the use-candidate attribute */
    avio_wb16(pb, STUN_ATTR_USE_CANDIDATE); /* attribute type use-candidate */
    avio_wb16(pb, 0); /* size of use-candidate */

    avio_wb16(pb, STUN_ATTR_PRIORITY);
    avio_wb16(pb, 4);
    avio_wb32(pb, STUN_HOST_CANDIDATE_PRIORITY);

    avio_wb16(pb, STUN_ATTR_ICE_CONTROLLING);
    avio_wb16(pb, 8);
    avio_wb64(pb, rtc->ice_tie_breaker);

    /* Build and update message integrity */
    avio_wb16(pb, STUN_ATTR_MESSAGE_INTEGRITY); /* attribute type message integrity */
    avio_wb16(pb, 20); /* size of message integrity */
    ffio_fill(pb, 0, 20); /* fill with zero to directly write and skip it */
    size = avio_tell(pb);
    buf[2] = (size - 20) >> 8;
    buf[3] = (size - 20) & 0xFF;
    av_hmac_init(hmac, rtc->ice_pwd_remote, strlen(rtc->ice_pwd_remote));
    av_hmac_update(hmac, buf, size - 24);
    av_hmac_final(hmac, buf + size - 20, 20);

    /* Write the fingerprint attribute */
    avio_wb16(pb, STUN_ATTR_FINGERPRINT); /* attribute type fingerprint */
    avio_wb16(pb, 4); /* size of fingerprint */
    ffio_fill(pb, 0, 4); /* fill with zero to directly write and skip it */
    size = avio_tell(pb);
    buf[2] = (size - 20) >> 8;
    buf[3] = (size - 20) & 0xFF;
    /* Refer to the av_hash_alloc("CRC32"), av_hash_init and av_hash_final */
    crc32 = av_crc(av_crc_get_table(AV_CRC_32_IEEE_LE), 0xFFFFFFFF, buf, size - 8) ^ 0xFFFFFFFF;
    avio_skip(pb, -4);
    avio_wb32(pb, crc32 ^ 0x5354554E); /* xor with "STUN" */

    *request_size = size;

end:
    avio_context_free(&pb);
    av_hmac_free(hmac);
    return ret;
}

/**
 * Create an ICE binding response.
 *
 * This function generates an ICE binding response and writes it to the provided
 * buffer. The response is signed using the local password for message integrity.
 *
 * @param s Pointer to the AVFormatContext structure.
 * @param tid Pointer to the transaction ID of the binding request. The tid_size should be 12.
 * @param tid_size The size of the transaction ID, should be 12.
 * @param buf Pointer to the buffer where the response will be written.
 * @param buf_size The size of the buffer provided for the response.
 * @param response_size Pointer to an integer that will store the size of the generated response.
 * @return Returns 0 if successful or AVERROR_xxx if an error occurs.
 */
int ff_rtc_ice_create_binding_response(RTCContext *rtc,
                                       char *tid, int tid_size,
                                       uint8_t *buf, int buf_size,
                                       int *response_size)
{
    int ret = 0, size, crc32;
    AVIOContext *pb = NULL;
    AVHMAC *hmac = NULL;

    if (tid_size != 12) {
        av_log(rtc->ctx->priv_data, AV_LOG_ERROR, "Invalid transaction ID size. Expected 12, got %d\n", tid_size);
        return AVERROR(EINVAL);
    }

    pb = avio_alloc_context(buf, buf_size, 1, NULL, NULL, NULL, NULL);
    if (!pb)
        return AVERROR(ENOMEM);

    hmac = av_hmac_alloc(AV_HMAC_SHA1);
    if (!hmac) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

    /* Write 20 bytes header */
    avio_wb16(pb, 0x0101); /* STUN binding response */
    avio_wb16(pb, 0);      /* length */
    avio_wb32(pb, STUN_MAGIC_COOKIE); /* magic cookie */
    avio_write(pb, tid, tid_size); /* transaction ID */

    /* Build and update message integrity */
    avio_wb16(pb, STUN_ATTR_MESSAGE_INTEGRITY); /* attribute type message integrity */
    avio_wb16(pb, 20); /* size of message integrity */
    ffio_fill(pb, 0, 20); /* fill with zero to directly write and skip it */
    size = avio_tell(pb);
    buf[2] = (size - 20) >> 8;
    buf[3] = (size - 20) & 0xFF;
    av_hmac_init(hmac, rtc->ice_pwd_local, strlen(rtc->ice_pwd_local));
    av_hmac_update(hmac, buf, size - 24);
    av_hmac_final(hmac, buf + size - 20, 20);

    /* Write the fingerprint attribute */
    avio_wb16(pb, STUN_ATTR_FINGERPRINT); /* attribute type fingerprint */
    avio_wb16(pb, 4); /* size of fingerprint */
    ffio_fill(pb, 0, 4); /* fill with zero to directly write and skip it */
    size = avio_tell(pb);
    buf[2] = (size - 20) >> 8;
    buf[3] = (size - 20) & 0xFF;
    /* Refer to the av_hash_alloc("CRC32"), av_hash_init and av_hash_final */
    crc32 = av_crc(av_crc_get_table(AV_CRC_32_IEEE_LE), 0xFFFFFFFF, buf, size - 8) ^ 0xFFFFFFFF;
    avio_skip(pb, -4);
    avio_wb32(pb, crc32 ^ 0x5354554E); /* xor with "STUN" */

    *response_size = size;

end:
    avio_context_free(&pb);
    av_hmac_free(hmac);
    return ret;
}

/**
 * A Binding request has class=0b00 (request) and method=0b000000000001 (Binding)
 * and is encoded into the first 16 bits as 0x0001.
 * See https://datatracker.ietf.org/doc/html/rfc5389#section-6
 */
int ff_rtc_ice_is_binding_request(uint8_t *b, int size)
{
    return size >= RTC_STUN_HEADER_SIZE && AV_RB16(&b[0]) == 0x0001;
}

/**
 * A Binding response has class=0b10 (success response) and method=0b000000000001,
 * and is encoded into the first 16 bits as 0x0101.
 */
int ff_rtc_ice_is_binding_response(uint8_t *b, int size)
{
    return size >= RTC_STUN_HEADER_SIZE && AV_RB16(&b[0]) == 0x0101;
}

/**
 * In RTP packets, the first byte is represented as 0b10xxxxxx, where the initial
 * two bits (0b10) indicate the RTP version,
 * see https://www.rfc-editor.org/rfc/rfc3550#section-5.1
 * The RTCP packet header is similar to RTP,
 * see https://www.rfc-editor.org/rfc/rfc3550#section-6.4.1
 */
int ff_rtc_is_rtp_or_rtcp(const uint8_t *b, int size)
{
    return size >= RTC_RTP_HEADER_SIZE && (b[0] & 0xC0) == 0x80;
}

/* Whether the packet is RTCP. */
int ff_rtc_is_rtcp(const uint8_t *b, int size)
{
    return size >= RTC_RTP_HEADER_SIZE && b[1] >= RTC_RTCP_PT_START && b[1] <= RTC_RTCP_PT_END;
}

/**
 * Get or Generate a self-signed certificate and private key for DTLS,
 * fingerprint for SDP
 */
av_cold int ff_rtc_init_certificate(RTCContext *rtc)
{
    int ret = 0;

    if (rtc->cert_file && rtc->key_file) {
        /* Read the private key and certificate from the file. */
        if ((ret = ff_ssl_read_key_cert(rtc->key_file, rtc->cert_file,
                                        rtc->key_buf, sizeof(rtc->key_buf),
                                        rtc->cert_buf, sizeof(rtc->cert_buf),
                                        &rtc->local_fingerprint)) < 0) {
            av_log(rtc->ctx->priv_data, AV_LOG_ERROR, "Failed to read DTLS certificate from cert=%s, key=%s\n",
                rtc->cert_file, rtc->key_file);
            return ret;
        }
    } else {
        /* Generate a private key to ctx->dtls_pkey and self-signed certificate. */
        if ((ret = ff_ssl_gen_key_cert(rtc->key_buf, sizeof(rtc->key_buf),
                                       rtc->cert_buf, sizeof(rtc->cert_buf),
                                       &rtc->local_fingerprint)) < 0) {
            av_log(rtc->ctx->priv_data, AV_LOG_ERROR, "Failed to generate DTLS private key and certificate\n");
            return ret;
        }
    }

    return ret;
}

av_cold int ff_rtc_dtls_open(RTCContext *rtc)
{
    int ret = 0;
    AVDictionary *opts = NULL;
    char buf[256];
    int is_dtls_active = rtc->flags & RTC_DTLS_ACTIVE;

    ff_url_join(buf, sizeof(buf), "dtls", NULL, rtc->ice_host, rtc->ice_port, NULL);
    av_dict_set_int(&opts, "mtu", rtc->pkt_size, 0);
    if (rtc->cert_file) {
        av_dict_set(&opts, "cert_file", rtc->cert_file, 0);
    } else
        av_dict_set(&opts, "cert_pem", rtc->cert_buf, 0);

    if (rtc->key_file) {
        av_dict_set(&opts, "key_file", rtc->key_file, 0);
    } else
        av_dict_set(&opts, "key_pem", rtc->key_buf, 0);
    av_dict_set_int(&opts, "external_sock", 1, 0);
    av_dict_set_int(&opts, "use_srtp", 1, 0);
    av_dict_set_int(&opts, "listen", is_dtls_active ? 0 : 1, 0);
    // Do not verify CA
    av_dict_set_int(&opts, "verify", 0, 0);
    ret = ffurl_open_whitelist(&rtc->dtls, buf, AVIO_FLAG_READ_WRITE, &rtc->ctx->interrupt_callback,
        &opts, rtc->ctx->protocol_whitelist, rtc->ctx->protocol_blacklist, NULL);
    av_dict_free(&opts);
    if (ret < 0) {
        av_log(rtc->ctx->priv_data, AV_LOG_ERROR, "Failed to open DTLS url:%s\n", buf);
        goto end;
    }
    /* reuse the udp socket created by the caller */
    ff_tls_set_external_socket(rtc->dtls, rtc->udp);
end:
    return ret;
}

int ff_rtc_session_init(RTCContext *rtc)
{
    int ret;
    uint32_t seed;

    ret = ff_rtc_init_certificate(rtc);
    if (ret < 0) {
        av_log(rtc->ctx->priv_data, AV_LOG_ERROR, "Failed to init certificate and key\n");
        return ret;
    }

    /* Initialize the random number generator. */
    seed = av_get_random_seed();
    av_lfg_init(&rtc->rnd, seed);

    /* 64 bit tie breaker for ICE-CONTROLLING (RFC 8445 16.1) */
    ret = av_random_bytes((uint8_t *)&rtc->ice_tie_breaker, sizeof(rtc->ice_tie_breaker));
    if (ret < 0) {
        av_log(rtc->ctx->priv_data, AV_LOG_ERROR, "Couldn't generate random bytes for ICE tie breaker\n");
        return ret;
    }

    if (rtc->state < RTC_STATE_INITIALIZED)
        rtc->state = RTC_STATE_INITIALIZED;
    rtc->init_time = av_gettime_relative();
    av_log(rtc->ctx->priv_data, AV_LOG_VERBOSE, "Init state=%d, handshake_timeout=%dms, pkt_size=%d, seed=%d, elapsed=%.2fms\n",
        rtc->state, rtc->handshake_timeout, rtc->pkt_size, seed, RTC_ELAPSED(rtc->start_time, av_gettime_relative()));

    return 0;
}

/**
 * Parses the ICE ufrag, pwd, and candidates from the SDP answer. It returns an
 * error if any of these fields is missing. Only the first host UDP candidate is
 * used; support for multiple candidates will be added in the future.
 */
int ff_rtc_parse_answer(RTCContext *rtc)
{
    int ret = 0;
    AVIOContext *pb;
    char line[MAX_URL_SIZE];
    const char *ptr;
    int i;

    if (!rtc->remote_sdp || !strlen(rtc->remote_sdp)) {
        av_log(rtc->ctx->priv_data, AV_LOG_ERROR, "No answer to parse\n");
        return AVERROR(EINVAL);
    }

    pb = avio_alloc_context(rtc->remote_sdp, strlen(rtc->remote_sdp), 0, NULL, NULL, NULL, NULL);
    if (!pb)
        return AVERROR(ENOMEM);

    for (i = 0; !avio_feof(pb); i++) {
        ff_get_chomp_line(pb, line, sizeof(line));
        if (av_strstart(line, "a=ice-lite", &ptr))
            rtc->is_peer_ice_lite = 1;
        if (av_strstart(line, "a=ice-ufrag:", &ptr) && !rtc->ice_ufrag_remote) {
            rtc->ice_ufrag_remote = av_strdup(ptr);
            if (!rtc->ice_ufrag_remote) {
                ret = AVERROR(ENOMEM);
                goto end;
            }
        } else if (av_strstart(line, "a=ice-pwd:", &ptr) && !rtc->ice_pwd_remote) {
            rtc->ice_pwd_remote = av_strdup(ptr);
            if (!rtc->ice_pwd_remote) {
                ret = AVERROR(ENOMEM);
                goto end;
            }
        } else if (av_strstart(line, "a=fingerprint:", &ptr) && !rtc->remote_fingerprint) {
            /* SDP a=fingerprint format is "<algo> <hex:hex:...>". Skip
             * the algo token, store the hex string for post-handshake compare. */
            const char *space = strchr(ptr, ' ');
            if (space) {
                rtc->remote_fingerprint = av_strdup(space + 1);
                if (!rtc->remote_fingerprint) {
                    ret = AVERROR(ENOMEM);
                    goto end;
                }
            }
        } else if (av_strstart(line, "a=candidate:", &ptr) && !rtc->ice_protocol) {
            if (ptr && av_stristr(ptr, "host")) {
                /* Refer to RFC 5245 15.1 */
                char foundation[33], protocol[17], host[129];
                int component_id, priority, port;
                ret = sscanf(ptr, "%32s %d %16s %d %128s %d typ host", foundation, &component_id, protocol, &priority, host, &port);
                if (ret != 6) {
                    av_log(rtc->ctx->priv_data, AV_LOG_ERROR, "Failed %d to parse line %d %s from %s\n",
                        ret, i, line, rtc->remote_sdp);
                    ret = AVERROR(EIO);
                    goto end;
                }

                if (av_strcasecmp(protocol, "udp")) {
                    av_log(rtc->ctx->priv_data, AV_LOG_ERROR, "Protocol %s is not supported by RTC, choose udp, line %d %s of %s\n",
                        protocol, i, line, rtc->remote_sdp);
                    ret = AVERROR(EIO);
                    goto end;
                }

                rtc->ice_protocol = av_strdup(protocol);
                rtc->ice_host = av_strdup(host);
                rtc->ice_port = port;
                if (!rtc->ice_protocol || !rtc->ice_host) {
                    ret = AVERROR(ENOMEM);
                    goto end;
                }
            }
        }
    }

    if (!rtc->ice_pwd_remote || !strlen(rtc->ice_pwd_remote)) {
        av_log(rtc->ctx->priv_data, AV_LOG_ERROR, "No remote ice pwd parsed from %s\n", rtc->remote_sdp);
        ret = AVERROR(EINVAL);
        goto end;
    }

    if (!rtc->ice_ufrag_remote || !strlen(rtc->ice_ufrag_remote)) {
        av_log(rtc->ctx->priv_data, AV_LOG_ERROR, "No remote ice ufrag parsed from %s\n", rtc->remote_sdp);
        ret = AVERROR(EINVAL);
        goto end;
    }

    if (!rtc->ice_protocol || !rtc->ice_host || !rtc->ice_port) {
        av_log(rtc->ctx->priv_data, AV_LOG_ERROR, "No ice candidate parsed from %s\n", rtc->remote_sdp);
        ret = AVERROR(EINVAL);
        goto end;
    }

    /* per RFC 8829/8842, SDP answer MUST carry a=fingerprint and that
     * fingerprint MUST match the DTLS peer certificate. Without it, an
     * on-path attacker can complete DTLS with an arbitrary self-signed
     * certificate and the resulting SRTP session is unauthenticated. */
    if (!rtc->remote_fingerprint || !strlen(rtc->remote_fingerprint)) {
        av_log(rtc->ctx->priv_data, AV_LOG_ERROR,
               "No remote DTLS fingerprint in SDP answer; refusing unauthenticated session\n");
        ret = AVERROR(EINVAL);
        goto end;
    }

    if (rtc->state < RTC_STATE_NEGOTIATED)
        rtc->state = RTC_STATE_NEGOTIATED;
    rtc->answer_time = av_gettime_relative();
    av_log(rtc->ctx->priv_data, AV_LOG_VERBOSE, "SDP state=%d, offer=%zuB, answer=%zuB, ufrag=%s, pwd=%zuB, transport=%s://%s:%d, elapsed=%.2fms\n",
        rtc->state, strlen(rtc->local_sdp), strlen(rtc->remote_sdp), rtc->ice_ufrag_remote, strlen(rtc->ice_pwd_remote),
        rtc->ice_protocol, rtc->ice_host, rtc->ice_port, RTC_ELAPSED(rtc->start_time, av_gettime_relative()));

end:
    avio_context_free(&pb);
    return ret;
}

/**
 * To establish a connection with the UDP server, we utilize ICE-LITE in a
 * Client-Server mode. In this setup, FFmpeg acts as the UDP client, while the
 * peer functions as the UDP server.
 */
int ff_rtc_udp_connect(RTCContext *rtc)
{
    int ret = 0;
    char url[256];
    AVDictionary *opts = NULL;

    /* Build UDP URL and create the UDP context as transport. */
    ff_url_join(url, sizeof(url), "udp", NULL, rtc->ice_host, rtc->ice_port, NULL);

    av_dict_set_int(&opts, "connect", 1, 0);
    av_dict_set_int(&opts, "fifo_size", 0, 0);
    /* Pass through the pkt_size and buffer_size to underling protocol */
    av_dict_set_int(&opts, "pkt_size", rtc->pkt_size, 0);
    av_dict_set_int(&opts, "buffer_size", rtc->buffer_size, 0);

    ret = ffurl_open_whitelist(&rtc->udp, url, AVIO_FLAG_WRITE, &rtc->ctx->interrupt_callback,
        &opts, rtc->ctx->protocol_whitelist, rtc->ctx->protocol_blacklist, NULL);
    if (ret < 0) {
        av_log(rtc->ctx->priv_data, AV_LOG_ERROR, "Failed to connect udp://%s:%d\n", rtc->ice_host, rtc->ice_port);
        goto end;
    }

    /* Make the socket non-blocking, set to READ and WRITE mode after connected */
    ff_socket_nonblock(ffurl_get_file_handle(rtc->udp), 1);
    rtc->udp->flags |= AVIO_FLAG_READ | AVIO_FLAG_NONBLOCK;

    if (rtc->state < RTC_STATE_UDP_CONNECTED)
        rtc->state = RTC_STATE_UDP_CONNECTED;
    rtc->udp_time = av_gettime_relative();
    av_log(rtc->ctx->priv_data, AV_LOG_VERBOSE, "UDP state=%d, elapsed=%.2fms, connected to udp://%s:%d\n",
        rtc->state, RTC_ELAPSED(rtc->start_time, av_gettime_relative()), rtc->ice_host, rtc->ice_port);

end:
    av_dict_free(&opts);
    return ret;
}

/**
 * This function handles incoming binding request messages by responding to them.
 * If the message is not a binding request, it will be ignored.
 */
int ff_rtc_ice_handle_binding_request(RTCContext *rtc, char *buf, int buf_size)
{
    int ret = 0, size;
    char tid[12];

    /* Ignore if not a binding request. */
    if (!ff_rtc_ice_is_binding_request(buf, buf_size))
        return ret;

    if (buf_size < RTC_STUN_HEADER_SIZE) {
        av_log(rtc->ctx->priv_data, AV_LOG_ERROR, "Invalid STUN message, expected at least %d, got %d\n",
            RTC_STUN_HEADER_SIZE, buf_size);
        return AVERROR(EINVAL);
    }

    /* Parse transaction id from binding request in buf. */
    memcpy(tid, buf + 8, 12);

    /* Build the STUN binding response. */
    ret = ff_rtc_ice_create_binding_response(rtc, tid, sizeof(tid), rtc->buf,
                                             sizeof(rtc->buf), &size);
    if (ret < 0) {
        av_log(rtc->ctx->priv_data, AV_LOG_ERROR, "Failed to create STUN binding response, size=%d\n", size);
        return ret;
    }

    ret = ffurl_write(rtc->udp, rtc->buf, size);
    if (ret < 0) {
        av_log(rtc->ctx->priv_data, AV_LOG_ERROR, "Failed to send STUN binding response, size=%d\n", size);
        return ret;
    }

    return 0;
}

int ff_rtc_ice_dtls_handshake(RTCContext *rtc)
{
    int ret = 0, size, i;
    int64_t starttime = av_gettime_relative(), now;
    int is_dtls_active = rtc->flags & RTC_DTLS_ACTIVE;

    if (rtc->state < RTC_STATE_UDP_CONNECTED || !rtc->udp) {
        av_log(rtc->ctx->priv_data, AV_LOG_ERROR, "UDP not connected, state=%d, udp=%p\n", rtc->state, rtc->udp);
        return AVERROR(EINVAL);
    }

    while (1) {
        if (rtc->state <= RTC_STATE_ICE_CONNECTING) {
            /* Build the STUN binding request. */
            ret = ff_rtc_ice_create_binding_request(rtc, rtc->buf, sizeof(rtc->buf),
                                                    &size);
            if (ret < 0) {
                av_log(rtc->ctx->priv_data, AV_LOG_ERROR, "Failed to create STUN binding request, size=%d\n", size);
                goto end;
            }

            ret = ffurl_write(rtc->udp, rtc->buf, size);
            if (ret < 0) {
                av_log(rtc->ctx->priv_data, AV_LOG_ERROR, "Failed to send STUN binding request, size=%d\n", size);
                goto end;
            }

            if (rtc->state < RTC_STATE_ICE_CONNECTING)
                rtc->state = RTC_STATE_ICE_CONNECTING;
        }

next_packet:
        if (rtc->state >= RTC_STATE_DTLS_CONNECTED)
            /* DTLS handshake is done, exit the loop. */
            break;

        now = av_gettime_relative();
        if (now - starttime >= rtc->handshake_timeout * RTC_US_PER_MS) {
            av_log(rtc->ctx->priv_data, AV_LOG_ERROR, "DTLS handshake timeout=%dms, cost=%.2fms, elapsed=%.2fms, state=%d\n",
                rtc->handshake_timeout, RTC_ELAPSED(starttime, now), RTC_ELAPSED(rtc->start_time, now), rtc->state);
            ret = AVERROR(ETIMEDOUT);
            goto end;
        }

        /* Read the STUN or DTLS messages from peer. */
        for (i = 0; i < RTC_ICE_DTLS_READ_MAX_RETRY; i++) {
            if (rtc->state > RTC_STATE_ICE_CONNECTED)
                break;
            ret = ffurl_read(rtc->udp, rtc->buf, sizeof(rtc->buf));
            if (ret > 0)
                break;
            if (ret == AVERROR(EAGAIN)) {
                av_usleep(RTC_ICE_DTLS_READ_SLEEP_DURATION * RTC_US_PER_MS);
                continue;
            }
            if (is_dtls_active)
                break;
            av_log(rtc->ctx->priv_data, AV_LOG_ERROR, "Failed to read message\n");
            goto end;
        }

        /* Handle the ICE binding response. */
        if (ff_rtc_ice_is_binding_response(rtc->buf, ret)) {
            if (rtc->state < RTC_STATE_ICE_CONNECTED) {
                if (rtc->is_peer_ice_lite)
                    rtc->state = RTC_STATE_ICE_CONNECTED;
            }
            goto next_packet;
        }

        /* When a binding request is received, it is necessary to respond immediately. */
        if (ff_rtc_ice_is_binding_request(rtc->buf, ret)) {
            if ((ret = ff_rtc_ice_handle_binding_request(rtc, rtc->buf, ret)) < 0)
                goto end;
            goto next_packet;
        }

        /* Handle DTLS handshake */
        if (ff_is_dtls_packet(rtc->buf, ret) || is_dtls_active) {
            rtc->ice_time = av_gettime_relative();
            /* Start consent timer when ICE selected */
            rtc->last_consent_tx_time = rtc->last_consent_rx_time = rtc->ice_time;
            rtc->state = RTC_STATE_ICE_CONNECTED;
            av_log(rtc->ctx->priv_data, AV_LOG_VERBOSE, "ICE STUN ok, state=%d, url=udp://%s:%d, username=%s:%s, res=%dB, elapsed=%.2fms\n",
                rtc->state, rtc->ice_host, rtc->ice_port,
                rtc->ice_ufrag_remote, rtc->ice_ufrag_local, ret, RTC_ELAPSED(rtc->start_time, rtc->ice_time));

            ret = ff_rtc_dtls_open(rtc);
            if (ret < 0)
                goto end;
            ret = ffurl_handshake(rtc->dtls);
            if (ret < 0) {
                rtc->state = RTC_STATE_FAILED;
                av_log(rtc->ctx->priv_data, AV_LOG_ERROR, "DTLS session failed\n");
                goto end;
            }
            if (!ret) {
                rtc->state = RTC_STATE_DTLS_CONNECTED;
                rtc->dtls_time = av_gettime_relative();
                av_log(rtc->ctx->priv_data, AV_LOG_VERBOSE, "DTLS handshake is done, elapsed=%.2fms\n",
                    RTC_ELAPSED(rtc->start_time, rtc->dtls_time));
            }
            goto next_packet;
        }
    }

end:
    return ret;
}

int ff_rtc_dtls_export_materials(RTCContext *rtc, char *send_key, char *recv_key)
{
    int ret;
    int is_dtls_active = rtc->flags & RTC_DTLS_ACTIVE;
    char *cp = is_dtls_active ? send_key : recv_key;
    char *sp = is_dtls_active ? recv_key : send_key;

    ret = ff_dtls_export_materials(rtc->dtls, rtc->dtls_srtp_materials, sizeof(rtc->dtls_srtp_materials));
    if (ret < 0)
        return ret;
    /**
     * This represents the material used to build the SRTP master key. It is
     * generated by DTLS and has the following layout:
     *          16B         16B         14B             14B
     *      client_key | server_key | client_salt | server_salt
     */
    char *client_key = rtc->dtls_srtp_materials;
    char *server_key = rtc->dtls_srtp_materials + RTC_DTLS_SRTP_KEY_LEN;
    char *client_salt = server_key + RTC_DTLS_SRTP_KEY_LEN;
    char *server_salt = client_salt + RTC_DTLS_SRTP_SALT_LEN;

    memcpy(cp, client_key, RTC_DTLS_SRTP_KEY_LEN);
    memcpy(cp + RTC_DTLS_SRTP_KEY_LEN, client_salt, RTC_DTLS_SRTP_SALT_LEN);

    memcpy(sp, server_key, RTC_DTLS_SRTP_KEY_LEN);
    memcpy(sp + RTC_DTLS_SRTP_KEY_LEN, server_salt, RTC_DTLS_SRTP_SALT_LEN);

    return 0;
}

void ff_rtc_session_deinit(RTCContext *rtc)
{
    av_freep(&rtc->local_sdp);
    av_freep(&rtc->remote_sdp);
    av_freep(&rtc->ice_ufrag_remote);
    av_freep(&rtc->ice_pwd_remote);
    av_freep(&rtc->ice_protocol);
    av_freep(&rtc->ice_host);
    av_freep(&rtc->authorization);
    av_freep(&rtc->cert_file);
    av_freep(&rtc->key_file);
    ffurl_closep(&rtc->dtls);
    ffurl_closep(&rtc->udp);
    av_freep(&rtc->local_fingerprint);
    av_freep(&rtc->remote_fingerprint);
}
