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

#include "libavutil/base64.h"
#include "libavutil/bprint.h"
#include "libavutil/channel_layout.h"
#include "libavutil/intreadwrite.h"
#include "libavutil/internal.h"
#include "libavutil/mem.h"
#include "libavutil/opt.h"
#include "libavutil/time.h"

#include "demux.h"
#include "internal.h"
#include "rtc.h"
#include "rtpdec.h"
#include "rtpdec_formats.h"
#include "srtp.h"
#include "tls.h"

#define WHEP_RTP_PAYLOAD_TYPE_H264 106
#define WHEP_RTP_PAYLOAD_TYPE_OPUS 111

#define WHEP_READ_TIMEOUT_US (10 * 1000000)
#define WHEP_PLI_INTERVAL_US (1 * 1000000)
#define WHEP_CONSENT_INTERVAL_US (2 * 1000000)

#define WHEP_AUDIO_CLOCK_RATE 48000
#define WHEP_VIDEO_CLOCK_RATE 90000

#define WHEP_SRTP_SUITE "SRTP_AES128_CM_HMAC_SHA1_80"

#define WHEP_SDP_SESSION_ID "4489045141692799359"
#define WHEP_SDP_CREATOR_IP "127.0.0.1"

typedef struct WHEPStream {
    RTPDemuxContext *rtp;
    PayloadContext *payload;
    const RTPDynamicProtocolHandler *handler;
    int payload_type;
} WHEPStream;

typedef struct WHEPContext {
    AVClass *av_class;

    RTCContext rtc;

    /* The RTP depacketizers, index 0 is audio and index 1 is video. */
    WHEPStream streams[2];
    /* 1 + the index of the stream that still has packets queued, or 0. */
    int pending;
    /* Base64 of the SRTP master key and salt used to decrypt incoming media. */
    char srtp_recv_key[AV_BASE64_SIZE(RTC_DTLS_SRTP_KEY_LEN + RTC_DTLS_SRTP_SALT_LEN)];

    /* The SRTP context used to encrypt outgoing RTCP (PLI). */
    SRTPContext srtp_rtcp_send;
    /* Time of the last PLI, and whether a keyframe has been received. */
    int64_t last_pli_time;
    int got_keyframe;
} WHEPContext;

/**
 * Generate the SDP offer for a receive-only session, with one audio (Opus)
 * and one video (H.264) media section.
 *
 * @return 0 if OK, AVERROR_xxx on error
 */
static int generate_sdp_offer(AVFormatContext *s)
{
    int ret = 0;
    AVBPrint bp;
    WHEPContext *whep = s->priv_data;
    RTCContext *rtc = &whep->rtc;

    /* To prevent a crash during cleanup, always initialize it. */
    av_bprint_init(&bp, 1, RTC_MAX_SDP_SIZE);

    if (rtc->sdp_offer) {
        av_log(whep, AV_LOG_ERROR, "SDP offer is already set\n");
        ret = AVERROR(EINVAL);
        goto end;
    }

    snprintf(rtc->ice_ufrag_local, sizeof(rtc->ice_ufrag_local), "%08x",
        av_lfg_get(&rtc->rnd));
    snprintf(rtc->ice_pwd_local, sizeof(rtc->ice_pwd_local), "%08x%08x%08x%08x",
        av_lfg_get(&rtc->rnd), av_lfg_get(&rtc->rnd), av_lfg_get(&rtc->rnd),
        av_lfg_get(&rtc->rnd));

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
        rtc->ice_ufrag_local,
        rtc->ice_pwd_local,
        rtc->dtls_fingerprint,
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
        "a=rtcp-fb:%u nack pli\r\n"
        "a=fmtp:%u level-asymmetry-allowed=1;packetization-mode=1\r\n",
        WHEP_RTP_PAYLOAD_TYPE_H264,
        rtc->ice_ufrag_local,
        rtc->ice_pwd_local,
        rtc->dtls_fingerprint,
        WHEP_RTP_PAYLOAD_TYPE_H264,
        WHEP_RTP_PAYLOAD_TYPE_H264,
        WHEP_RTP_PAYLOAD_TYPE_H264);

    if (!av_bprint_is_complete(&bp)) {
        av_log(whep, AV_LOG_ERROR, "Offer exceed max %d, %s\n", RTC_MAX_SDP_SIZE, bp.str);
        ret = AVERROR(EIO);
        goto end;
    }

    rtc->sdp_offer = av_strdup(bp.str);
    if (!rtc->sdp_offer) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

    if (rtc->state < RTC_STATE_OFFER)
        rtc->state = RTC_STATE_OFFER;
    rtc->offer_time = av_gettime_relative();
    av_log(whep, AV_LOG_VERBOSE, "Generated state=%d, offer: %s\n", rtc->state, rtc->sdp_offer);

end:
    av_bprint_finalize(&bp, NULL);
    return ret;
}

/**
 * Derive the SRTP receive key from the keying material exported from DTLS
 * and keep it for the RTP demuxers. WHEP does not send media, so unlike
 * whip.c there are no send contexts.
 *
 * @return 0 if OK, AVERROR_xxx on error
 */
static int setup_srtp(AVFormatContext *s)
{
    int ret;
    char recv_key[RTC_DTLS_SRTP_KEY_LEN + RTC_DTLS_SRTP_SALT_LEN];
    char send_key[RTC_DTLS_SRTP_KEY_LEN + RTC_DTLS_SRTP_SALT_LEN];
    char buf[AV_BASE64_SIZE(RTC_DTLS_SRTP_KEY_LEN + RTC_DTLS_SRTP_SALT_LEN)];
    /**
     * The profile for OpenSSL's SRTP is SRTP_AES128_CM_SHA1_80, see ssl/d1_srtp.c.
     * The profile for FFmpeg's SRTP is SRTP_AES128_CM_HMAC_SHA1_80, see libavformat/srtp.c.
     */
    const char *suite = WHEP_SRTP_SUITE;
    WHEPContext *whep = s->priv_data;
    RTCContext *rtc = &whep->rtc;
    int is_dtls_active = rtc->flags & RTC_DTLS_ACTIVE;
    char *cp = is_dtls_active ? send_key : recv_key;
    char *sp = is_dtls_active ? recv_key : send_key;
    char *client_key, *server_key, *client_salt, *server_salt;

    ret = ff_dtls_export_materials(rtc->dtls_uc, rtc->dtls_srtp_materials,
                                   sizeof(rtc->dtls_srtp_materials));
    if (ret < 0)
        goto end;

    /**
     * This represents the material used to build the SRTP master key. It is
     * generated by DTLS and has the following layout:
     *          16B         16B         14B             14B
     *      client_key | server_key | client_salt | server_salt
     */
    client_key = rtc->dtls_srtp_materials;
    server_key = client_key + RTC_DTLS_SRTP_KEY_LEN;
    client_salt = server_key + RTC_DTLS_SRTP_KEY_LEN;
    server_salt = client_salt + RTC_DTLS_SRTP_SALT_LEN;

    memcpy(cp, client_key, RTC_DTLS_SRTP_KEY_LEN);
    memcpy(cp + RTC_DTLS_SRTP_KEY_LEN, client_salt, RTC_DTLS_SRTP_SALT_LEN);

    memcpy(sp, server_key, RTC_DTLS_SRTP_KEY_LEN);
    memcpy(sp + RTC_DTLS_SRTP_KEY_LEN, server_salt, RTC_DTLS_SRTP_SALT_LEN);

    if (!av_base64_encode(buf, sizeof(buf), recv_key, sizeof(recv_key))) {
        av_log(whep, AV_LOG_ERROR, "Failed to encode recv key\n");
        ret = AVERROR(EIO);
        goto end;
    }

    memcpy(whep->srtp_recv_key, buf, sizeof(whep->srtp_recv_key));

    if (!av_base64_encode(buf, sizeof(buf), send_key, sizeof(send_key))) {
        av_log(whep, AV_LOG_ERROR, "Failed to encode send key\n");
        ret = AVERROR(EIO);
        goto end;
    }

    ret = ff_srtp_set_crypto(&whep->srtp_rtcp_send, suite, buf);
    if (ret < 0) {
        av_log(whep, AV_LOG_ERROR, "Failed to set crypto for rtcp send\n");
        goto end;
    }

    if (rtc->state < RTC_STATE_SRTP_FINISHED)
        rtc->state = RTC_STATE_SRTP_FINISHED;
    rtc->srtp_time = av_gettime_relative();
    av_log(whep, AV_LOG_VERBOSE, "SRTP setup done, state=%d, suite=%s, key=%zuB, elapsed=%.2fms\n",
        rtc->state, suite, sizeof(recv_key), RTC_ELAPSED(rtc->starttime, av_gettime_relative()));

end:
    return ret;
}

/**
 * Create a stream and the RTP depacketizer that feeds it. Each stream gets its
 * own SRTP context, since sequence numbers and ROC are tracked per SSRC.
 *
 * @return 0 if OK, AVERROR_xxx on error
 */
static int add_rtp_stream(AVFormatContext *s, int index, enum AVMediaType type,
                          const RTPDynamicProtocolHandler *handler,
                          int payload_type, int clock_rate)
{
    int ret;
    AVStream *st;
    AVCodecParameters *par;
    WHEPContext *whep = s->priv_data;
    WHEPStream *ws = &whep->streams[index];

    st = avformat_new_stream(s, NULL);
    if (!st)
        return AVERROR(ENOMEM);

    par = st->codecpar;
    par->codec_type = type;
    par->codec_id   = handler->codec_id;
    if (type == AVMEDIA_TYPE_AUDIO) {
        par->sample_rate = clock_rate;
        av_channel_layout_default(&par->ch_layout, 2);
    }
    avpriv_set_pts_info(st, 32, 1, clock_rate);
    ffstream(st)->need_parsing = handler->need_parsing;

    ws->handler      = handler;
    ws->payload_type = payload_type;
    if (handler->priv_data_size) {
        ws->payload = av_mallocz(handler->priv_data_size);
        if (!ws->payload)
            return AVERROR(ENOMEM);
    }

    /* No reordering queue for now, packets are expected in order. */
    ws->rtp = ff_rtp_parse_open(s, st, payload_type, 0);
    if (!ws->rtp)
        return AVERROR(ENOMEM);
    ff_rtp_parse_set_dynamic_protocol(ws->rtp, ws->payload, handler);

    if (handler->init && (ret = handler->init(s, st->index, ws->payload)) < 0)
        return ret;

    ff_rtp_parse_set_crypto(ws->rtp, WHEP_SRTP_SUITE, whep->srtp_recv_key);
    if (!ws->rtp->srtp_enabled) {
        av_log(whep, AV_LOG_ERROR, "Failed to set crypto for stream %d\n", index);
        return AVERROR(EINVAL);
    }

    return 0;
}

static int create_streams(AVFormatContext *s)
{
    int ret;
    WHEPContext *whep = s->priv_data;
    RTCContext *rtc = &whep->rtc;

    ret = add_rtp_stream(s, 0, AVMEDIA_TYPE_AUDIO, &ff_opus_dynamic_handler,
                         WHEP_RTP_PAYLOAD_TYPE_OPUS, WHEP_AUDIO_CLOCK_RATE);
    if (ret < 0)
        return ret;

    ret = add_rtp_stream(s, 1, AVMEDIA_TYPE_VIDEO, &ff_h264_dynamic_handler,
                         WHEP_RTP_PAYLOAD_TYPE_H264, WHEP_VIDEO_CLOCK_RATE);
    if (ret < 0)
        return ret;

    if (rtc->state < RTC_STATE_READY)
        rtc->state = RTC_STATE_READY;
    av_log(whep, AV_LOG_VERBOSE, "Streams created, state=%d, elapsed=%.2fms\n",
        rtc->state, RTC_ELAPSED(rtc->starttime, av_gettime_relative()));

    return 0;
}

/**
 * Check whether a decrypted H.264 RTP packet carries the start of a keyframe
 * (IDR or SPS, single NAL unit or the first FU-A fragment). STAP-A is not
 * inspected.
 */
static int rtp_h264_is_keyframe(const uint8_t *buf, int len)
{
    int off = 12 + 4 * (buf[0] & 0x0f), nal;

    if ((buf[0] & 0x10) && len >= off + 4)
        off += 4 + 4 * AV_RB16(buf + off + 2);
    if (len < off + 2)
        return 0;

    nal = buf[off] & 0x1f;
    if (nal == 28) {
        if (!(buf[off + 1] & 0x80))
            return 0;
        nal = buf[off + 1] & 0x1f;
    }
    return nal == 5 || nal == 7;
}

/**
 * Send a Picture Loss Indication (RFC 4585) so the server sends a keyframe.
 * Without one, a late joiner cannot decode video until the next keyframe.
 */
static void send_pli(AVFormatContext *s, uint32_t media_ssrc)
{
    uint8_t pli[12], out[sizeof(pli) + 16];
    WHEPContext *whep = s->priv_data;
    RTCContext *rtc = &whep->rtc;
    int ret;

    pli[0] = 0x81;      /* V=2, FMT=1 (PLI) */
    pli[1] = 206;       /* PSFB */
    AV_WB16(pli + 2, 2);
    AV_WB32(pli + 4, media_ssrc + 1);
    AV_WB32(pli + 8, media_ssrc);

    ret = ff_srtp_encrypt(&whep->srtp_rtcp_send, pli, sizeof(pli), out, sizeof(out));
    if (ret <= 0) {
        av_log(whep, AV_LOG_WARNING, "Failed to encrypt PLI, ret=%d\n", ret);
        return;
    }

    ret = ffurl_write(rtc->udp, out, ret);
    if (ret < 0)
        av_log(whep, AV_LOG_WARNING, "Failed to send PLI, ret=%d\n", ret);
    else
        av_log(whep, AV_LOG_DEBUG, "PLI sent for ssrc=%u\n", media_ssrc);
}

/**
 * Send an ICE binding request as a keepalive (RFC 7675 consent freshness),
 * otherwise the server drops the session after its timeout (30s on SRS).
 */
static void send_consent(AVFormatContext *s)
{
    int ret, size;
    WHEPContext *whep = s->priv_data;
    RTCContext *rtc = &whep->rtc;

    ret = ff_rtc_ice_create_request(rtc, rtc->buf, sizeof(rtc->buf), &size);
    if (ret < 0) {
        av_log(whep, AV_LOG_WARNING, "Failed to create consent request\n");
        return;
    }

    ret = ffurl_write(rtc->udp, rtc->buf, size);
    if (ret < 0)
        av_log(whep, AV_LOG_WARNING, "Failed to send consent request, ret=%d\n", ret);
    else
        rtc->last_consent_tx_time = av_gettime_relative();
}

static int whep_read_packet(AVFormatContext *s, AVPacket *pkt)
{
    int ret, i, pt, size;
    uint8_t *buf;
    WHEPContext *whep = s->priv_data;
    RTCContext *rtc = &whep->rtc;
    int64_t last_rx = av_gettime_relative();

    /* Return the packets still queued from the previous RTP packet first. */
    if (whep->pending) {
        ret = ff_rtp_parse_packet(whep->streams[whep->pending - 1].rtp, pkt, NULL, 0);
        if (ret <= 0)
            whep->pending = 0;
        if (ret >= 0)
            return 0;
    }

    while (1) {
        if (ff_check_interrupt(&s->interrupt_callback))
            return AVERROR_EXIT;

        if (av_gettime_relative() - rtc->last_consent_tx_time > WHEP_CONSENT_INTERVAL_US)
            send_consent(s);

        ret = ffurl_read(rtc->udp, rtc->buf, sizeof(rtc->buf));
        if (ret == AVERROR(EAGAIN)) {
            if (av_gettime_relative() - last_rx > WHEP_READ_TIMEOUT_US) {
                av_log(whep, AV_LOG_ERROR, "No packets received for %d seconds\n",
                       WHEP_READ_TIMEOUT_US / 1000000);
                return AVERROR(ETIMEDOUT);
            }
            av_usleep(RTC_ICE_DTLS_READ_SLEEP_DURATION * RTC_US_PER_MS);
            continue;
        }
        if (ret < 0)
            return ret;

        last_rx = av_gettime_relative();
        buf = (uint8_t *)rtc->buf;

        if (ff_rtc_ice_is_binding_request(buf, ret)) {
            if ((ret = ff_rtc_ice_handle_binding_request(rtc, rtc->buf, ret)) < 0)
                return ret;
            continue;
        }

        /* Drop STUN responses, DTLS and RTCP. RTCP is not handled yet. */
        if (!ff_rtc_media_is_rtp_rtcp(buf, ret) || ff_rtc_media_is_rtcp(buf, ret))
            continue;

        pt = buf[1] & 0x7f;
        for (i = 0; i < FF_ARRAY_ELEMS(whep->streams); i++)
            if (whep->streams[i].payload_type == pt)
                break;
        if (i == FF_ARRAY_ELEMS(whep->streams))
            continue;

        size = ret;
        ret = ff_rtp_parse_packet(whep->streams[i].rtp, pkt, &buf, ret);
        if (i == 1 && !whep->got_keyframe &&
            av_gettime_relative() - whep->last_pli_time > WHEP_PLI_INTERVAL_US) {
            whep->last_pli_time = av_gettime_relative();
            send_pli(s, whep->streams[1].rtp->ssrc);
        }
        /* The packet was decrypted in place, inspect it for a keyframe. */
        if (i == 1 && !whep->got_keyframe && size > 14 &&
            rtp_h264_is_keyframe((uint8_t *)rtc->buf, size))
            whep->got_keyframe = 1;
        if (ret < 0)
            continue;
        if (ret > 0)
            whep->pending = i + 1;
        return 0;
    }
}

static av_cold int whep_init(AVFormatContext *s)
{
    int ret;
    WHEPContext *whep = s->priv_data;
    RTCContext *rtc = &whep->rtc;

    rtc->ctx = s;
    rtc->starttime = av_gettime_relative();

    if ((ret = ff_rtc_initialize(rtc)) < 0)
        goto end;

    if ((ret = generate_sdp_offer(s)) < 0)
        goto end;

    if ((ret = ff_rtc_exchange_sdp(rtc)) < 0)
        goto end;

    if ((ret = ff_rtc_parse_answer(rtc)) < 0)
        goto end;

    /**
     * Our offer uses a=setup:actpass, so the server picks the DTLS role.
     * SRS always answers a=setup:passive, which makes us the DTLS client.
     * Reading a=setup: from the answer is not implemented yet.
     */
    rtc->flags |= RTC_DTLS_ACTIVE;

    if ((ret = ff_rtc_udp_connect(rtc)) < 0)
        goto end;

    if ((ret = ff_rtc_ice_dtls_handshake(rtc)) < 0)
        goto end;

    if ((ret = setup_srtp(s)) < 0)
        goto end;

    if ((ret = create_streams(s)) < 0)
        goto end;

end:
    if (ret < 0)
        rtc->state = RTC_STATE_FAILED;
    return ret;
}

static av_cold int whep_close(AVFormatContext *s)
{
    int ret;
    WHEPContext *whep = s->priv_data;
    RTCContext *rtc = &whep->rtc;

    ret = ff_rtc_dispose_session(rtc);
    if (ret < 0)
        av_log(whep, AV_LOG_WARNING, "Failed to dispose resource, ret=%d\n", ret);

    for (int i = 0; i < FF_ARRAY_ELEMS(whep->streams); i++) {
        WHEPStream *ws = &whep->streams[i];

        if (ws->rtp)
            ff_rtp_parse_close(ws->rtp);
        if (ws->payload) {
            if (ws->handler && ws->handler->close)
                ws->handler->close(ws->payload);
            av_freep(&ws->payload);
        }
    }

    ff_srtp_free(&whep->srtp_rtcp_send);
    ff_rtc_deinit(rtc);

    return 0;
}

#define RTC_OFFSET(x) (offsetof(WHEPContext, rtc) + offsetof(RTCContext, x))
#define DEC AV_OPT_FLAG_DECODING_PARAM
static const AVOption options[] = {
    { "handshake_timeout",  "Timeout in milliseconds for ICE and DTLS handshake.",      RTC_OFFSET(handshake_timeout),  AV_OPT_TYPE_INT,      { .i64 = 5000 }, -1, INT_MAX, DEC },
    { "timeout",            "Set timeout for socket I/O operations",                    RTC_OFFSET(timeout),            AV_OPT_TYPE_DURATION, { .i64 = -1 },   -1, INT_MAX, DEC },
    { "pkt_size",           "The maximum size, in bytes, of RTP packets expected in",   RTC_OFFSET(pkt_size),           AV_OPT_TYPE_INT,      { .i64 = 1200 }, -1, INT_MAX, DEC },
    { "ts_buffer_size",     "The buffer size, in bytes, of underlying protocol",        RTC_OFFSET(ts_buffer_size),     AV_OPT_TYPE_INT,      { .i64 = -1 },   -1, INT_MAX, DEC },
    { "authorization",      "The optional Bearer token for WHEP Authorization",         RTC_OFFSET(authorization),      AV_OPT_TYPE_STRING,   { .str = NULL },  0, 0,       DEC },
    { "cert_file",          "The optional certificate file path for DTLS",              RTC_OFFSET(cert_file),          AV_OPT_TYPE_STRING,   { .str = NULL },  0, 0,       DEC },
    { "key_file",           "The optional private key file path for DTLS",              RTC_OFFSET(key_file),           AV_OPT_TYPE_STRING,   { .str = NULL },  0, 0,       DEC },
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
    .flags_internal = FF_INFMT_FLAG_INIT_CLEANUP,
    .read_header    = whep_init,
    .read_packet    = whep_read_packet,
    .read_close     = whep_close,
};
