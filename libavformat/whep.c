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
#include "libavutil/mem.h"
#include "libavutil/opt.h"
#include "libavutil/time.h"

#include "demux.h"
#include "internal.h"
#include "rtc.h"

#define WHEP_RTP_PAYLOAD_TYPE_H264 106
#define WHEP_RTP_PAYLOAD_TYPE_OPUS 111

#define WHEP_SDP_SESSION_ID "4489045141692799359"
#define WHEP_SDP_CREATOR_IP "127.0.0.1"

typedef struct WHEPContext {
    AVClass *av_class;

    RTCContext rtc;
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
        "a=fmtp:%u level-asymmetry-allowed=1;packetization-mode=1\r\n",
        WHEP_RTP_PAYLOAD_TYPE_H264,
        rtc->ice_ufrag_local,
        rtc->ice_pwd_local,
        rtc->dtls_fingerprint,
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

static int whep_read_packet(AVFormatContext *s, AVPacket *pkt)
{
    /* RTP receive and depacketization are not implemented yet. */
    return AVERROR(ENOSYS);
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
