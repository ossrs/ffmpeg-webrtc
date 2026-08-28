/*
 * WebRTC-HTTP egress protocol (WHEP) demuxer
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

#include "libavutil/bprint.h"
#include "libavutil/internal.h"
#include "libavutil/lfg.h"
#include "libavutil/opt.h"
#include "libavutil/mem.h"
#include "libavutil/random_seed.h"
#include "libavutil/time.h"

#include "avio_internal.h"
#include "demux.h"
#include "http.h"
#include "internal.h"
#include "network.h"
#include "rtc.h"
#include "tls.h"

#define WHEP_RTP_PAYLOAD_TYPE_H264 106
#define WHEP_RTP_PAYLOAD_TYPE_OPUS 111

#define WHEP_SDP_SESSION_ID "4489045141692799359"
#define WHEP_SDP_CREATOR_IP "127.0.0.1"

#define ELAPSED(starttime, endtime) ((float)(endtime - starttime) / 1000)

#define MAX_UDP_BUFFER_SIZE 4096
#define ICE_DTLS_READ_MAX_RETRY 10
#define ICE_DTLS_READ_SLEEP_DURATION 5

enum WHEPState {
    WHEP_STATE_NONE,
    WHEP_STATE_INIT,
    WHEP_STATE_OFFER,
    WHEP_STATE_ANSWER,
    WHEP_STATE_NEGOTIATED,
    WHEP_STATE_UDP_CONNECTED,
    WHEP_STATE_ICE_CONNECTING,
    WHEP_STATE_ICE_CONNECTED,
    WHEP_STATE_DTLS_FINISHED,
    WHEP_STATE_FAILED,
};

typedef struct WHEPContext {
    AVClass *av_class;
    enum WHEPState state;

    RTCContext rtc;

    /* The UDP transport is used for delivering ICE, DTLS and SRTP packets. */
    URLContext *udp;
    /* The DTLS transport, established over the UDP socket above. */
    URLContext *dtls_uc;
    /* The buffer for UDP transmission. */
    char buf[MAX_UDP_BUFFER_SIZE];

    char *sdp_offer;
    char *sdp_answer;
    char *whep_resource_url;

    int64_t whep_starttime;

    char cert_buf[MAX_CERTIFICATE_SIZE];
    char key_buf[MAX_CERTIFICATE_SIZE];
    char *dtls_fingerprint;
    char *remote_fingerprint;

    int64_t timeout;
    /* Timeout in milliseconds for ICE and DTLS handshake. */
    int64_t handshake_timeout;
    /* The maximum size, in bytes, of RTP packets expected over the UDP transport. */
    int pkt_size;
    char *authorization;
    char *cert_file;
    char *key_file;
} WHEPContext;

static av_cold int certificate_key_init(AVFormatContext *s)
{
    WHEPContext *whep = s->priv_data;

    return ff_rtc_init_certificate(s, whep->key_file, whep->cert_file,
                                   whep->key_buf, sizeof(whep->key_buf),
                                   whep->cert_buf, sizeof(whep->cert_buf),
                                   &whep->dtls_fingerprint);
}

static av_cold int initialize(AVFormatContext *s)
{
    int ret;
    WHEPContext *whep = s->priv_data;
    uint32_t seed;

    whep->rtc.ctx = s;
    whep->whep_starttime = av_gettime_relative();

    ret = certificate_key_init(s);
    if (ret < 0) {
        av_log(whep, AV_LOG_ERROR, "Failed to init certificate and key\n");
        return ret;
    }

    seed = av_get_random_seed();
    av_lfg_init(&whep->rtc.rnd, seed);

    /* 64 bit tie breaker for ICE-CONTROLLING (RFC 8445 16.1) */
    ret = av_random_bytes((uint8_t *)&whep->rtc.ice_tie_breaker, sizeof(whep->rtc.ice_tie_breaker));
    if (ret < 0) {
        av_log(whep, AV_LOG_ERROR, "Couldn't generate random bytes for ICE tie breaker\n");
        return ret;
    }

    if (whep->state < WHEP_STATE_INIT)
        whep->state = WHEP_STATE_INIT;
    av_log(whep, AV_LOG_VERBOSE, "Init state=%d, seed=%d, elapsed=%.2fms\n",
        whep->state, seed, ELAPSED(whep->whep_starttime, av_gettime_relative()));

    return 0;
}

static int generate_sdp_offer(AVFormatContext *s)
{
    int ret = 0;
    AVBPrint bp;
    WHEPContext *whep = s->priv_data;

    av_bprint_init(&bp, 1, RTC_MAX_SDP_SIZE);

    if (whep->sdp_offer) {
        av_log(whep, AV_LOG_ERROR, "SDP offer is already set\n");
        ret = AVERROR(EINVAL);
        goto end;
    }

    snprintf(whep->rtc.ice_ufrag_local, sizeof(whep->rtc.ice_ufrag_local), "%08x",
        av_lfg_get(&whep->rtc.rnd));
    snprintf(whep->rtc.ice_pwd_local, sizeof(whep->rtc.ice_pwd_local), "%08x%08x%08x%08x",
        av_lfg_get(&whep->rtc.rnd), av_lfg_get(&whep->rtc.rnd), av_lfg_get(&whep->rtc.rnd),
        av_lfg_get(&whep->rtc.rnd));

    av_bprintf(&bp, ""
        "v=0\r\n"
        "o=FFmpeg %s 2 IN IP4 %s\r\n"
        "s=FFmpegPlaySession\r\n"
        "t=0 0\r\n"
        "a=group:BUNDLE 0 1\r\n"
        "a=extmap-allow-mixed\r\n",
        WHEP_SDP_SESSION_ID,
        WHEP_SDP_CREATOR_IP);

    av_bprintf(&bp, ""
        "m=audio 9 UDP/TLS/RTP/SAVPF %u\r\n"
        "c=IN IP4 0.0.0.0\r\n"
        "a=rtcp:9 IN IP4 0.0.0.0\r\n"
        "a=ice-ufrag:%s\r\n"
        "a=ice-pwd:%s\r\n"
        "a=fingerprint:sha-256 %s\r\n"
        "a=setup:actpass\r\n"
        "a=mid:0\r\n"
        "a=recvonly\r\n"
        "a=rtcp-mux\r\n"
        "a=rtcp-mux-only\r\n"
        "a=rtpmap:%u opus/48000/2\r\n",
        WHEP_RTP_PAYLOAD_TYPE_OPUS,
        whep->rtc.ice_ufrag_local,
        whep->rtc.ice_pwd_local,
        whep->dtls_fingerprint,
        WHEP_RTP_PAYLOAD_TYPE_OPUS);

    av_bprintf(&bp, ""
        "m=video 9 UDP/TLS/RTP/SAVPF %u\r\n"
        "c=IN IP4 0.0.0.0\r\n"
        "a=rtcp:9 IN IP4 0.0.0.0\r\n"
        "a=ice-ufrag:%s\r\n"
        "a=ice-pwd:%s\r\n"
        "a=fingerprint:sha-256 %s\r\n"
        "a=setup:actpass\r\n"
        "a=mid:1\r\n"
        "a=recvonly\r\n"
        "a=rtcp-mux\r\n"
        "a=rtcp-mux-only\r\n"
        "a=rtpmap:%u H264/90000\r\n"
        "a=fmtp:%u level-asymmetry-allowed=1;packetization-mode=1\r\n",
        WHEP_RTP_PAYLOAD_TYPE_H264,
        whep->rtc.ice_ufrag_local,
        whep->rtc.ice_pwd_local,
        whep->dtls_fingerprint,
        WHEP_RTP_PAYLOAD_TYPE_H264,
        WHEP_RTP_PAYLOAD_TYPE_H264);

    if (!av_bprint_is_complete(&bp)) {
        av_log(whep, AV_LOG_ERROR, "Offer exceed max %d, %s\n", RTC_MAX_SDP_SIZE, bp.str);
        ret = AVERROR(EIO);
        goto end;
    }

    whep->sdp_offer = av_strdup(bp.str);
    if (!whep->sdp_offer) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

    if (whep->state < WHEP_STATE_OFFER)
        whep->state = WHEP_STATE_OFFER;
    av_log(whep, AV_LOG_VERBOSE, "Generated state=%d, offer: %s\n", whep->state, whep->sdp_offer);

end:
    av_bprint_finalize(&bp, NULL);
    return ret;
}

static int exchange_sdp(AVFormatContext *s)
{
    int ret;
    char buf[MAX_URL_SIZE];
    AVBPrint bp;
    WHEPContext *whep = s->priv_data;
    URLContext *whep_uc = NULL;
    AVDictionary *opts = NULL;
    char *hex_data = NULL;
    const char *proto_name = avio_find_protocol_name(s->url);

    av_bprint_init(&bp, 1, RTC_MAX_SDP_SIZE);

    if (!av_strstart(proto_name, "http", NULL)) {
        av_log(whep, AV_LOG_ERROR, "Protocol %s is not supported by RTC, choose http, url is %s\n",
            proto_name, s->url);
        ret = AVERROR(EINVAL);
        goto end;
    }

    if (!whep->sdp_offer || !strlen(whep->sdp_offer)) {
        av_log(whep, AV_LOG_ERROR, "No offer to exchange\n");
        ret = AVERROR(EINVAL);
        goto end;
    }

    ret = snprintf(buf, sizeof(buf), "Cache-Control: no-cache\r\nContent-Type: application/sdp\r\n");
    if (whep->authorization)
        ret += snprintf(buf + ret, sizeof(buf) - ret, "Authorization: Bearer %s\r\n", whep->authorization);
    if (ret <= 0 || ret >= sizeof(buf)) {
        av_log(whep, AV_LOG_ERROR, "Failed to generate headers, size=%d, %s\n", ret, buf);
        ret = AVERROR(EINVAL);
        goto end;
    }

    av_dict_set(&opts, "headers", buf, 0);
    av_dict_set_int(&opts, "chunked_post", 0, 0);

    if (whep->timeout >= 0)
        av_dict_set_int(&opts, "timeout", whep->timeout, 0);

    hex_data = av_mallocz(2 * strlen(whep->sdp_offer) + 1);
    if (!hex_data) {
        ret = AVERROR(ENOMEM);
        goto end;
    }
    ff_data_to_hex(hex_data, whep->sdp_offer, strlen(whep->sdp_offer), 0);
    av_dict_set(&opts, "post_data", hex_data, 0);

    ret = ffurl_open_whitelist(&whep_uc, s->url, AVIO_FLAG_READ_WRITE, &s->interrupt_callback,
        &opts, s->protocol_whitelist, s->protocol_blacklist, NULL);
    if (ret < 0) {
        av_log(whep, AV_LOG_ERROR, "Failed to request url=%s, offer: %s\n", s->url, whep->sdp_offer);
        goto end;
    }

    if (ff_http_get_new_location(whep_uc)) {
        whep->whep_resource_url = av_strdup(ff_http_get_new_location(whep_uc));
        if (!whep->whep_resource_url) {
            ret = AVERROR(ENOMEM);
            goto end;
        }
    }

    while (1) {
        ret = ffurl_read(whep_uc, buf, sizeof(buf));
        if (ret == AVERROR_EOF) {
            ret = 0;
            break;
        }
        if (ret <= 0) {
            av_log(whep, AV_LOG_ERROR, "Failed to read response from url=%s, offer is %s, answer is %s\n",
                s->url, whep->sdp_offer, whep->sdp_answer);
            goto end;
        }

        av_bprintf(&bp, "%.*s", ret, buf);
        if (!av_bprint_is_complete(&bp)) {
            av_log(whep, AV_LOG_ERROR, "Answer exceed max size %d, %.*s, %s\n", RTC_MAX_SDP_SIZE, ret, buf, bp.str);
            ret = AVERROR(EIO);
            goto end;
        }
    }

    if (!av_strstart(bp.str, "v=", NULL)) {
        av_log(whep, AV_LOG_ERROR, "Invalid answer: %s\n", bp.str);
        ret = AVERROR(EINVAL);
        goto end;
    }

    whep->sdp_answer = av_strdup(bp.str);
    if (!whep->sdp_answer) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

    if (whep->state < WHEP_STATE_ANSWER)
        whep->state = WHEP_STATE_ANSWER;
    av_log(whep, AV_LOG_VERBOSE, "Got state=%d, answer: %s\n", whep->state, whep->sdp_answer);

end:
    ffurl_closep(&whep_uc);
    av_bprint_finalize(&bp, NULL);
    av_dict_free(&opts);
    av_freep(&hex_data);
    return ret;
}

static int parse_answer(AVFormatContext *s)
{
    int ret = 0;
    AVIOContext *pb;
    char line[MAX_URL_SIZE];
    const char *ptr;
    int i;
    WHEPContext *whep = s->priv_data;

    if (!whep->sdp_answer || !strlen(whep->sdp_answer)) {
        av_log(whep, AV_LOG_ERROR, "No answer to parse\n");
        return AVERROR(EINVAL);
    }

    pb = avio_alloc_context(whep->sdp_answer, strlen(whep->sdp_answer), 0, NULL, NULL, NULL, NULL);
    if (!pb)
        return AVERROR(ENOMEM);

    for (i = 0; !avio_feof(pb); i++) {
        ff_get_chomp_line(pb, line, sizeof(line));
        if (av_strstart(line, "a=ice-lite", &ptr))
            whep->rtc.is_peer_ice_lite = 1;
        if (av_strstart(line, "a=ice-ufrag:", &ptr) && !whep->rtc.ice_ufrag_remote) {
            whep->rtc.ice_ufrag_remote = av_strdup(ptr);
            if (!whep->rtc.ice_ufrag_remote) {
                ret = AVERROR(ENOMEM);
                goto end;
            }
        } else if (av_strstart(line, "a=ice-pwd:", &ptr) && !whep->rtc.ice_pwd_remote) {
            whep->rtc.ice_pwd_remote = av_strdup(ptr);
            if (!whep->rtc.ice_pwd_remote) {
                ret = AVERROR(ENOMEM);
                goto end;
            }
        } else if (av_strstart(line, "a=fingerprint:", &ptr) && !whep->remote_fingerprint) {
            /* per RFC 8829/8842, SDP answer MUST carry a=fingerprint and that
             * fingerprint MUST match the DTLS peer certificate. */
            const char *space = strchr(ptr, ' ');
            if (space) {
                whep->remote_fingerprint = av_strdup(space + 1);
                if (!whep->remote_fingerprint) {
                    ret = AVERROR(ENOMEM);
                    goto end;
                }
            }
        } else if (av_strstart(line, "a=candidate:", &ptr) && !whep->rtc.ice_protocol) {
            if (ptr && av_stristr(ptr, "host")) {
                /* Refer to RFC 5245 15.1 */
                char foundation[33], protocol[17], host[129];
                int component_id, priority, port;
                ret = sscanf(ptr, "%32s %d %16s %d %128s %d typ host", foundation, &component_id, protocol, &priority, host, &port);
                if (ret != 6) {
                    av_log(whep, AV_LOG_ERROR, "Failed %d to parse line %d %s from %s\n",
                        ret, i, line, whep->sdp_answer);
                    ret = AVERROR(EIO);
                    goto end;
                }

                if (av_strcasecmp(protocol, "udp")) {
                    av_log(whep, AV_LOG_ERROR, "Protocol %s is not supported by RTC, choose udp, line %d %s of %s\n",
                        protocol, i, line, whep->sdp_answer);
                    ret = AVERROR(EIO);
                    goto end;
                }

                whep->rtc.ice_protocol = av_strdup(protocol);
                whep->rtc.ice_host = av_strdup(host);
                whep->rtc.ice_port = port;
                if (!whep->rtc.ice_protocol || !whep->rtc.ice_host) {
                    ret = AVERROR(ENOMEM);
                    goto end;
                }
            }
        }
    }

    if (!whep->rtc.ice_pwd_remote || !strlen(whep->rtc.ice_pwd_remote)) {
        av_log(whep, AV_LOG_ERROR, "No remote ice pwd parsed from %s\n", whep->sdp_answer);
        ret = AVERROR(EINVAL);
        goto end;
    }

    if (!whep->rtc.ice_ufrag_remote || !strlen(whep->rtc.ice_ufrag_remote)) {
        av_log(whep, AV_LOG_ERROR, "No remote ice ufrag parsed from %s\n", whep->sdp_answer);
        ret = AVERROR(EINVAL);
        goto end;
    }

    if (!whep->rtc.ice_protocol || !whep->rtc.ice_host || !whep->rtc.ice_port) {
        av_log(whep, AV_LOG_ERROR, "No ice candidate parsed from %s\n", whep->sdp_answer);
        ret = AVERROR(EINVAL);
        goto end;
    }

    if (!whep->remote_fingerprint || !strlen(whep->remote_fingerprint)) {
        av_log(whep, AV_LOG_ERROR,
               "No remote DTLS fingerprint in SDP answer; refusing unauthenticated session\n");
        ret = AVERROR(EINVAL);
        goto end;
    }

    if (whep->state < WHEP_STATE_NEGOTIATED)
        whep->state = WHEP_STATE_NEGOTIATED;
    av_log(whep, AV_LOG_VERBOSE, "SDP state=%d, offer=%zuB, answer=%zuB, ufrag=%s, pwd=%zuB, transport=%s://%s:%d, elapsed=%.2fms\n",
        whep->state, strlen(whep->sdp_offer), strlen(whep->sdp_answer), whep->rtc.ice_ufrag_remote, strlen(whep->rtc.ice_pwd_remote),
        whep->rtc.ice_protocol, whep->rtc.ice_host, whep->rtc.ice_port, ELAPSED(whep->whep_starttime, av_gettime_relative()));

end:
    avio_context_free(&pb);
    return ret;
}

/**
 * DTLS role (active/passive) should ideally be read from the peer's
 * a=setup: line in the SDP answer (RFC 8842): if the peer says "passive",
 * we must be "active", and vice versa. This is not yet implemented; SRS
 * (the server used for testing) always answers with a=setup:passive, so
 * hardcoding the WHEP side as DTLS-active is correct against it, but this
 * is a known simplification to be replaced with real a=setup: parsing in
 * a follow-up patch.
 */
static av_cold int dtls_initialize(AVFormatContext *s)
{
    WHEPContext *whep = s->priv_data;
    const int is_dtls_active = 1;

    return ff_rtc_dtls_open(whep, s, &whep->dtls_uc, whep->udp,
                            whep->rtc.ice_host, whep->rtc.ice_port, whep->pkt_size,
                            whep->cert_file, whep->key_file,
                            whep->cert_buf, whep->key_buf, is_dtls_active);
}

static int ice_handle_binding_request(AVFormatContext *s, char *buf, int buf_size)
{
    int ret = 0, size;
    char tid[12];
    WHEPContext *whep = s->priv_data;

    if (!ff_rtc_ice_is_binding_request(buf, buf_size))
        return ret;

    if (buf_size < RTC_STUN_HEADER_SIZE) {
        av_log(whep, AV_LOG_ERROR, "Invalid STUN message, expected at least %d, got %d\n",
            RTC_STUN_HEADER_SIZE, buf_size);
        return AVERROR(EINVAL);
    }

    memcpy(tid, buf + 8, 12);

    ret = ff_rtc_ice_create_binding_response(&whep->rtc, tid, sizeof(tid), whep->buf,
                                             sizeof(whep->buf), &size);
    if (ret < 0) {
        av_log(whep, AV_LOG_ERROR, "Failed to create STUN binding response, size=%d\n", size);
        return ret;
    }

    ret = ffurl_write(whep->udp, whep->buf, size);
    if (ret < 0) {
        av_log(whep, AV_LOG_ERROR, "Failed to send STUN binding response, size=%d\n", size);
        return ret;
    }

    return 0;
}

static int udp_connect(AVFormatContext *s)
{
    int ret = 0;
    char url[256];
    AVDictionary *opts = NULL;
    WHEPContext *whep = s->priv_data;

    ff_url_join(url, sizeof(url), "udp", NULL, whep->rtc.ice_host, whep->rtc.ice_port, NULL);
    av_dict_set_int(&opts, "connect", 1, 0);
    av_dict_set_int(&opts, "fifo_size", 0, 0);

    ret = ffurl_open_whitelist(&whep->udp, url, AVIO_FLAG_WRITE, &s->interrupt_callback,
        &opts, s->protocol_whitelist, s->protocol_blacklist, NULL);
    if (ret < 0) {
        av_log(whep, AV_LOG_ERROR, "Failed to connect udp://%s:%d\n", whep->rtc.ice_host, whep->rtc.ice_port);
        goto end;
    }

    ff_socket_nonblock(ffurl_get_file_handle(whep->udp), 1);
    whep->udp->flags |= AVIO_FLAG_READ | AVIO_FLAG_NONBLOCK;

    if (whep->state < WHEP_STATE_UDP_CONNECTED)
        whep->state = WHEP_STATE_UDP_CONNECTED;
    av_log(whep, AV_LOG_VERBOSE, "UDP state=%d, elapsed=%.2fms, connected to udp://%s:%d\n",
        whep->state, ELAPSED(whep->whep_starttime, av_gettime_relative()), whep->rtc.ice_host, whep->rtc.ice_port);

end:
    av_dict_free(&opts);
    return ret;
}

static int ice_dtls_handshake(AVFormatContext *s)
{
    int ret = 0, size, i;
    int64_t starttime = av_gettime_relative(), now;
    WHEPContext *whep = s->priv_data;
    const int is_dtls_active = 1;

    if (whep->state < WHEP_STATE_UDP_CONNECTED || !whep->udp) {
        av_log(whep, AV_LOG_ERROR, "UDP not connected, state=%d, udp=%p\n", whep->state, whep->udp);
        return AVERROR(EINVAL);
    }

    while (1) {
        if (whep->state <= WHEP_STATE_ICE_CONNECTING) {
            ret = ff_rtc_ice_create_binding_request(&whep->rtc, whep->buf, sizeof(whep->buf),
                                                    &size);
            if (ret < 0) {
                av_log(whep, AV_LOG_ERROR, "Failed to create STUN binding request, size=%d\n", size);
                goto end;
            }

            ret = ffurl_write(whep->udp, whep->buf, size);
            if (ret < 0) {
                av_log(whep, AV_LOG_ERROR, "Failed to send STUN binding request, size=%d\n", size);
                goto end;
            }

            if (whep->state < WHEP_STATE_ICE_CONNECTING)
                whep->state = WHEP_STATE_ICE_CONNECTING;
        }

next_packet:
        if (whep->state >= WHEP_STATE_DTLS_FINISHED)
            break;

        now = av_gettime_relative();
        if (now - starttime >= whep->handshake_timeout * 1000) {
            av_log(whep, AV_LOG_ERROR, "DTLS handshake timeout=%dms, cost=%.2fms, elapsed=%.2fms, state=%d\n",
                (int)whep->handshake_timeout, ELAPSED(starttime, now), ELAPSED(whep->whep_starttime, now), whep->state);
            ret = AVERROR(ETIMEDOUT);
            goto end;
        }

        for (i = 0; i < ICE_DTLS_READ_MAX_RETRY; i++) {
            if (whep->state > WHEP_STATE_ICE_CONNECTED)
                break;
            ret = ffurl_read(whep->udp, whep->buf, sizeof(whep->buf));
            if (ret > 0)
                break;
            if (ret == AVERROR(EAGAIN)) {
                av_usleep(ICE_DTLS_READ_SLEEP_DURATION * 1000);
                continue;
            }
            if (is_dtls_active)
                break;
            av_log(whep, AV_LOG_ERROR, "Failed to read message\n");
            goto end;
        }

        if (ff_rtc_ice_is_binding_response(whep->buf, ret)) {
            if (whep->state < WHEP_STATE_ICE_CONNECTED) {
                if (whep->rtc.is_peer_ice_lite)
                    whep->state = WHEP_STATE_ICE_CONNECTED;
            }
            goto next_packet;
        }

        if (ff_rtc_ice_is_binding_request(whep->buf, ret)) {
            if ((ret = ice_handle_binding_request(s, whep->buf, ret)) < 0)
                goto end;
            goto next_packet;
        }

        if (ff_is_dtls_packet(whep->buf, ret) || is_dtls_active) {
            whep->state = WHEP_STATE_ICE_CONNECTED;
            av_log(whep, AV_LOG_VERBOSE, "ICE STUN ok, state=%d, url=udp://%s:%d, username=%s:%s, res=%dB, elapsed=%.2fms\n",
                whep->state, whep->rtc.ice_host, whep->rtc.ice_port,
                whep->rtc.ice_ufrag_remote, whep->rtc.ice_ufrag_local, ret, ELAPSED(whep->whep_starttime, av_gettime_relative()));

            ret = dtls_initialize(s);
            if (ret < 0)
                goto end;
            ret = ffurl_handshake(whep->dtls_uc);
            if (ret < 0) {
                whep->state = WHEP_STATE_FAILED;
                av_log(whep, AV_LOG_ERROR, "DTLS session failed\n");
                goto end;
            }
            if (!ret) {
                whep->state = WHEP_STATE_DTLS_FINISHED;
                av_log(whep, AV_LOG_VERBOSE, "DTLS handshake is done, elapsed=%.2fms\n",
                    ELAPSED(whep->whep_starttime, av_gettime_relative()));
            }
            goto next_packet;
        }
    }

end:
    return ret;
}

static int whep_read_packet(AVFormatContext *s, AVPacket *pkt)
{
    /* RTP receive/depacketization is not implemented yet; deferred to a
     * follow-up patch. */
    return AVERROR(ENOSYS);
}

static av_cold int whep_init(AVFormatContext *s)
{
    int ret;
    WHEPContext *whep = s->priv_data;

    if ((ret = initialize(s)) < 0)
        goto end;

    if ((ret = generate_sdp_offer(s)) < 0)
        goto end;

    if ((ret = exchange_sdp(s)) < 0)
        goto end;

    if ((ret = parse_answer(s)) < 0)
        goto end;

    if ((ret = udp_connect(s)) < 0)
        goto end;

    if ((ret = ice_dtls_handshake(s)) < 0)
        goto end;

end:
    if (ret < 0)
        whep->state = WHEP_STATE_FAILED;
    return ret;
}

#define OFFSET(x) offsetof(WHEPContext, x)
#define DEC AV_OPT_FLAG_DECODING_PARAM
static const AVOption options[] = {
    { "handshake_timeout",  "Timeout in milliseconds for ICE and DTLS handshake",       OFFSET(handshake_timeout),  AV_OPT_TYPE_INT,    { .i64 = 5000 },    -1, INT_MAX, DEC },
    { "pkt_size",           "The maximum size, in bytes, of RTP packets expected in",   OFFSET(pkt_size),           AV_OPT_TYPE_INT,    { .i64 = 1200 },    -1, INT_MAX, DEC },
    { "timeout",            "Set timeout for socket I/O operations",                    OFFSET(timeout),            AV_OPT_TYPE_DURATION, { .i64 = -1 }, -1, INT_MAX, DEC },
    { "authorization",      "The optional Bearer token for WHEP Authorization",         OFFSET(authorization),      AV_OPT_TYPE_STRING, { .str = NULL },     0,       0, DEC },
    { "cert_file",          "The optional certificate file path for DTLS",              OFFSET(cert_file),          AV_OPT_TYPE_STRING, { .str = NULL },     0,       0, DEC },
    { "key_file",           "The optional private key file path for DTLS",              OFFSET(key_file),           AV_OPT_TYPE_STRING, { .str = NULL },     0,       0, DEC },
    { NULL },
};

static const AVClass whep_demuxer_class = {
    .class_name = "WHEP demuxer",
    .item_name  = av_default_item_name,
    .option     = options,
    .version    = LIBAVUTIL_VERSION_INT,
};

const FFInputFormat ff_whep_demuxer = {
    .p.name         = "whep",
    .p.long_name    = NULL_IF_CONFIG_SMALL("WHEP(WebRTC-HTTP egress protocol) demuxer"),
    .p.flags        = AVFMT_NOFILE | AVFMT_EXPERIMENTAL,
    .p.priv_class   = &whep_demuxer_class,
    .priv_data_size = sizeof(WHEPContext),
    .read_header    = whep_init,
    .read_packet    = whep_read_packet,
};
