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

#include "libavcodec/h264.h"
#include "libavutil/attributes_internal.h"
#include "libavutil/avassert.h"
#include "libavutil/crc.h"
#include "libavutil/hmac.h"
#include "libavutil/intreadwrite.h"
#include "libavutil/avstring.h"
#include "libavutil/random_seed.h"
#include "libavutil/mem.h"
#include "libavutil/time.h"
#include "libavcodec/startcode.h"

#include "nal.h"
#include "avc.h"
#include "avio_internal.h"
#include "internal.h"
#include "mux.h"
#include "network.h"
#include "tls.h"
#include "srtp.h"
#include "rtc.h"

/**
 * If we try to read from UDP and get EAGAIN, we sleep for 5ms and retry up to 10 times.
 * This will limit the total duration (in milliseconds, 50ms)
 */
#define RTC_ICE_DTLS_READ_MAX_RETRY 10
#define RTC_ICE_DTLS_READ_SLEEP_DURATION 5

/**
 * Refer to RFC 7675 5.1,
 *
 * To prevent expiry of consent, a STUN binding request can be sent periodically.
 * Implementations SHOULD set a default interval of 5 seconds(5000ms).
 *
 * Consent expires after 30 seconds(30000ms).
 */
#define RTC_ICE_CONSENT_CHECK_INTERVAL 5000
#define RTC_ICE_CONSENT_EXPIRED_TIMER 30000


/* The magic cookie for Session Traversal Utilities for NAT (STUN) messages. */
#define STUN_MAGIC_COOKIE 0x2112A442

/**
 * Refer to RFC 8445 5.1.2
 * priority = (2^24)*(type preference) + (2^8)*(local preference) + (2^0)*(256 - component ID)
 * host candidate priority is 126 << 24 | 65535 << 8 | 255
 */
#define STUN_HOST_CANDIDATE_PRIORITY 126 << 24 | 65535 << 8 | 255

/* Referring to Chrome's definition of RTP payload types. */
#define RTC_RTP_PAYLOAD_TYPE_H264 106
#define RTC_RTP_PAYLOAD_TYPE_OPUS 111
#define RTC_RTP_PAYLOAD_TYPE_VIDEO_RTX 105

/**
 * In the case of ICE-LITE, these fields are not used; instead, they are defined
 * as constant values.
 */
#define RTC_SDP_SESSION_ID "4489045141692799359"
#define RTC_SDP_CREATOR_IP "127.0.0.1"

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
 * When duplicating a stream, the demuxer has already set the extradata, profile, and
 * level of the par. Keep in mind that this function will not be invoked since the
 * profile and level are set.
 *
 * When utilizing an encoder, such as libx264, to encode a stream, the extradata in
 * par->extradata contains the SPS, which includes profile and level information.
 * However, the profile and level of par remain unspecified. Therefore, it is necessary
 * to extract the profile and level data from the extradata and assign it to the par's
 * profile and level. Keep in mind that AVFMT_GLOBALHEADER must be enabled; otherwise,
 * the extradata will remain empty.
 */
static int parse_profile_level(RTCContext *rtc, AVCodecParameters *par)
{
    int ret = 0;
    const uint8_t *r = par->extradata, *r1, *end = par->extradata + par->extradata_size;
    H264SPS seq, *const sps = &seq;
    uint32_t state;
    AVFormatContext *s = rtc->ctx;

    if (par->codec_id != AV_CODEC_ID_H264)
        return ret;

    if (par->profile != AV_PROFILE_UNKNOWN && par->level != AV_LEVEL_UNKNOWN)
        return ret;

    if (!par->extradata || par->extradata_size <= 0) {
        av_log(s, AV_LOG_ERROR, "Unable to parse profile from empty extradata=%p, size=%d\n",
            par->extradata, par->extradata_size);
        return AVERROR(EINVAL);
    }

    while (1) {
        r = avpriv_find_start_code(r, end, &state);
        if (r >= end)
            break;

        r1 = ff_nal_find_startcode(r, end);
        if ((state & 0x1f) == H264_NAL_SPS) {
            ret = ff_avc_decode_sps(sps, r, r1 - r);
            if (ret < 0) {
                av_log(s, AV_LOG_ERROR, "Failed to decode SPS, state=%x, size=%d\n",
                    state, (int)(r1 - r));
                return ret;
            }

            av_log(s, AV_LOG_VERBOSE, "Parse profile=%d, level=%d from SPS\n",
                sps->profile_idc, sps->level_idc);
            par->profile = sps->profile_idc;
            par->level = sps->level_idc;
        }

        r = r1;
    }

    return ret;
}

/**
 * Parses video SPS/PPS from the extradata of codecpar and checks the codec.
 * Currently only supports video(h264) and audio(opus). Note that only baseline
 * and constrained baseline profiles of h264 are supported.
 *
 * If the profile is less than 0, the function considers the profile as baseline.
 * It may need to parse the profile from SPS/PPS. This situation occurs when ingesting
 * desktop and transcoding.
 *
 * @param s Pointer to the AVFormatContext
 * @returns Returns 0 if successful or AVERROR_xxx in case of an error.
 *
 * TODO: FIXME: There is an issue with the timestamp of OPUS audio, especially when
 *  the input is an MP4 file. The timestamp deviates from the expected value of 960,
 *  causing Chrome to play the audio stream with noise. This problem can be replicated
 *  by transcoding a specific file into MP4 format and publishing it using the WHIP
 *  muxer. However, when directly transcoding and publishing through the WHIP muxer,
 *  the issue is not present, and the audio timestamp remains consistent. The root
 *  cause is still unknown, and this comment has been added to address this issue
 *  in the future. Further research is needed to resolve the problem.
 */
static int parse_codec(RTCContext *rtc)
{
    int i, ret = 0;
    AVFormatContext *s = rtc->ctx;

    for (i = 0; i < s->nb_streams; i++) {
        AVCodecParameters *par = s->streams[i]->codecpar;
        switch (par->codec_type) {
        case AVMEDIA_TYPE_VIDEO:
            rtc->video_par = par;

            if (par->video_delay > 0) {
                av_log(s, AV_LOG_ERROR, "Unsupported B frames by RTC\n");
                return AVERROR_PATCHWELCOME;
            }

            if ((ret = parse_profile_level(rtc, par)) < 0) {
                av_log(s, AV_LOG_ERROR, "Failed to parse SPS/PPS from extradata\n");
                return AVERROR(EINVAL);
            }

            if (par->profile == AV_PROFILE_UNKNOWN) {
                av_log(s, AV_LOG_WARNING, "No profile found in extradata, consider baseline\n");
                return AVERROR(EINVAL);
            }
            if (par->level == AV_LEVEL_UNKNOWN) {
                av_log(s, AV_LOG_WARNING, "No level found in extradata, consider 3.1\n");
                return AVERROR(EINVAL);
            }
            break;
        case AVMEDIA_TYPE_AUDIO:
            rtc->audio_par = par;

            if (par->ch_layout.nb_channels != 2) {
                av_log(s, AV_LOG_ERROR, "Unsupported audio channels %d by RTC, choose stereo\n",
                    par->ch_layout.nb_channels);
                return AVERROR_PATCHWELCOME;
            }

            if (par->sample_rate != 48000) {
                av_log(s, AV_LOG_ERROR, "Unsupported audio sample rate %d by RTC, choose 48000\n", par->sample_rate);
                return AVERROR_PATCHWELCOME;
            }
            break;
        default:
            av_unreachable("already checked via FF_OFMT flags");
        }
    }

    return ret;
}

/**
 * Generate SDP offer according to the codec parameters, DTLS and ICE information.
 *
 * Note that we don't use av_sdp_create to generate SDP offer because it doesn't
 * support DTLS and ICE information.
 *
 * @return 0 if OK, AVERROR_xxx on error
 */
int rtc_generate_sdp_offer(RTCContext *rtc, char **sdp_offer, int is_dtls_active)
{
    char *sdp = NULL;
    int ret = 0, profile_idc = 0, level, profile_iop = 0;
    const char *acodec_name = NULL, *vcodec_name = NULL;
    char bundle[4];
    int bundle_index = 0;
    AVBPrint bp;

    /* To prevent a crash during cleanup, always initialize it. */
    av_bprint_init(&bp, 1, RTC_MAX_SDP_SIZE);

    snprintf(rtc->ice_ufrag_local, sizeof(rtc->ice_ufrag_local), "%08x",
        av_lfg_get(&rtc->rnd));
    snprintf(rtc->ice_pwd_local, sizeof(rtc->ice_pwd_local), "%08x%08x%08x%08x",
        av_lfg_get(&rtc->rnd), av_lfg_get(&rtc->rnd), av_lfg_get(&rtc->rnd),
        av_lfg_get(&rtc->rnd));

    rtc->audio_ssrc = av_lfg_get(&rtc->rnd);
    rtc->video_ssrc = rtc->audio_ssrc + 1;
    rtc->video_rtx_ssrc = rtc->video_ssrc + 1;

    rtc->audio_payload_type = RTC_RTP_PAYLOAD_TYPE_OPUS;
    rtc->video_payload_type = RTC_RTP_PAYLOAD_TYPE_H264;
    rtc->video_rtx_payload_type = RTC_RTP_PAYLOAD_TYPE_VIDEO_RTX;

    if (rtc->audio_par) {
        bundle[bundle_index++] = '0';
        bundle[bundle_index++] = ' ';
    }
    if (rtc->video_par) {
        bundle[bundle_index++] = '1';
        bundle[bundle_index++] = ' ';
    }
    bundle[bundle_index - 1] = '\0';

    av_bprintf(&bp, ""
        "v=0\r\n"
        "o=FFmpeg %s 2 IN IP4 %s\r\n"
        "s=FFmpegPublishSession\r\n"
        "t=0 0\r\n"
        "a=group:BUNDLE %s\r\n"
        "a=extmap-allow-mixed\r\n"
        "a=msid-semantic: WMS\r\n",
        RTC_SDP_SESSION_ID,
        RTC_SDP_CREATOR_IP,
        bundle);

    if (rtc->audio_par) {
        if (rtc->audio_par->codec_id == AV_CODEC_ID_OPUS)
            acodec_name = "opus";

        av_bprintf(&bp, ""
            "m=audio 9 UDP/TLS/RTP/SAVPF %u\r\n"
            "c=IN IP4 0.0.0.0\r\n"
            "a=ice-ufrag:%s\r\n"
            "a=ice-pwd:%s\r\n"
            "a=fingerprint:sha-256 %s\r\n"
            "a=setup:%s\r\n"
            "a=mid:0\r\n"
            "a=sendonly\r\n"
            "a=msid:FFmpeg audio\r\n"
            "a=rtcp-mux\r\n"
            "a=rtpmap:%u %s/%d/%d\r\n"
            "a=ssrc:%u cname:FFmpeg\r\n"
            "a=ssrc:%u msid:FFmpeg audio\r\n",
            rtc->audio_payload_type,
            rtc->ice_ufrag_local,
            rtc->ice_pwd_local,
            rtc->dtls_fingerprint,
            is_dtls_active ? "active" : "passive",
            rtc->audio_payload_type,
            acodec_name,
            rtc->audio_par->sample_rate,
            rtc->audio_par->ch_layout.nb_channels,
            rtc->audio_ssrc,
            rtc->audio_ssrc);
    }

    if (rtc->video_par) {
        level = rtc->video_par->level;
        if (rtc->video_par->codec_id == AV_CODEC_ID_H264) {
            vcodec_name = "H264";
            profile_iop |= rtc->video_par->profile & AV_PROFILE_H264_CONSTRAINED ? 1 << 6 : 0;
            profile_iop |= rtc->video_par->profile & AV_PROFILE_H264_INTRA ? 1 << 4 : 0;
            profile_idc = rtc->video_par->profile & 0x00ff;
        }

        av_bprintf(&bp, ""
            "m=video 9 UDP/TLS/RTP/SAVPF %u %u\r\n"
            "c=IN IP4 0.0.0.0\r\n"
            "a=ice-ufrag:%s\r\n"
            "a=ice-pwd:%s\r\n"
            "a=fingerprint:sha-256 %s\r\n"
            "a=setup:%s\r\n"
            "a=mid:1\r\n"
            "a=sendonly\r\n"
            "a=msid:FFmpeg video\r\n"
            "a=rtcp-mux\r\n"
            "a=rtcp-rsize\r\n"
            "a=rtpmap:%u %s/90000\r\n"
            "a=fmtp:%u level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=%02x%02x%02x\r\n"
            "a=rtcp-fb:%u nack\r\n"
            "a=rtpmap:%u rtx/90000\r\n"
            "a=fmtp:%u apt=%u\r\n"
            "a=ssrc-group:FID %u %u\r\n"
            "a=ssrc:%u cname:FFmpeg\r\n"
            "a=ssrc:%u msid:FFmpeg video\r\n",
            rtc->video_payload_type,
            rtc->video_rtx_payload_type,
            rtc->ice_ufrag_local,
            rtc->ice_pwd_local,
            rtc->dtls_fingerprint,
            is_dtls_active ? "active" : "passive",
            rtc->video_payload_type,
            vcodec_name,
            rtc->video_payload_type,
            profile_idc,
            profile_iop,
            level,
            rtc->video_payload_type,
            rtc->video_rtx_payload_type,
            rtc->video_rtx_payload_type,
            rtc->video_payload_type,
            rtc->video_ssrc,
            rtc->video_rtx_ssrc,
            rtc->video_ssrc,
            rtc->video_ssrc);
    }

    if (!av_bprint_is_complete(&bp)) {
        av_log(rtc->ctx, AV_LOG_ERROR, "Offer exceed max %d, %s\n", RTC_MAX_SDP_SIZE, bp.str);
        ret = AVERROR(EIO);
        goto end;
    }

    sdp = av_strdup(bp.str);
    if (!sdp) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

    if (rtc->state < RTC_STATE_OFFER)
        rtc->state = RTC_STATE_OFFER;
    av_log(rtc->ctx, AV_LOG_VERBOSE, "Generated state=%d, offer: %s\n", rtc->state, sdp);


end:
    av_bprint_finalize(&bp, NULL);
    *sdp_offer = sdp;
    return ret;
}

/**
 * Parses the ICE ufrag, pwd, and candidates from the SDP answer.
 *
 * This function is used to extract the ICE ufrag, pwd, and candidates from the SDP answer.
 * It returns an error if any of these fields is NULL. The function only uses the first
 * candidate if there are multiple candidates. However, support for multiple candidates
 * will be added in the future.
 *
 * @param s Pointer to the AVFormatContext
 * @returns Returns 0 if successful or AVERROR_xxx if an error occurs.
 */
int rtc_parse_answer(RTCContext *rtc, char *sdp_answer)
{
    int ret = 0;
    AVIOContext *pb;
    char line[MAX_URL_SIZE];
    const char *ptr;
    int i;

    if (!sdp_answer || !strlen(sdp_answer)) {
        av_log(rtc->ctx, AV_LOG_ERROR, "No answer to parse\n");
        return AVERROR(EINVAL);
    }

    pb = avio_alloc_context(sdp_answer, strlen(sdp_answer), 0, NULL, NULL, NULL, NULL);
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
                    av_log(rtc->ctx, AV_LOG_ERROR, "Failed %d to parse line %d %s from %s\n",
                        ret, i, line, sdp_answer);
                    ret = AVERROR(EIO);
                    goto end;
                }

                if (av_strcasecmp(protocol, "udp")) {
                    av_log(rtc->ctx, AV_LOG_ERROR, "Protocol %s is not supported by RTC, choose udp, line %d %s of %s\n",
                        protocol, i, line, sdp_answer);
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
        av_log(rtc->ctx, AV_LOG_ERROR, "No remote ice pwd parsed from %s\n", sdp_answer);
        ret = AVERROR(EINVAL);
        goto end;
    }

    if (!rtc->ice_ufrag_remote || !strlen(rtc->ice_ufrag_remote)) {
        av_log(rtc->ctx, AV_LOG_ERROR, "No remote ice ufrag parsed from %s\n", sdp_answer);
        ret = AVERROR(EINVAL);
        goto end;
    }

    if (!rtc->ice_protocol || !rtc->ice_host || !rtc->ice_port) {
        av_log(rtc->ctx, AV_LOG_ERROR, "No ice candidate parsed from %s\n", sdp_answer);
        ret = AVERROR(EINVAL);
        goto end;
    }

    /* per RFC 8829/8842, SDP answer MUST carry a=fingerprint and that
     * fingerprint MUST match the DTLS peer certificate. Without it, an
     * on-path attacker can complete DTLS with an arbitrary self-signed
     * certificate and the resulting SRTP session is unauthenticated. */
    if (!rtc->remote_fingerprint || !strlen(rtc->remote_fingerprint)) {
        av_log(rtc->ctx, AV_LOG_ERROR,
               "No remote DTLS fingerprint in SDP answer; refusing unauthenticated session\n");
        ret = AVERROR(EINVAL);
        goto end;
    }

    if (rtc->state < RTC_STATE_NEGOTIATED)
        rtc->state = RTC_STATE_NEGOTIATED;

end:
    avio_context_free(&pb);
    return ret;
}

/**
 * This function handles incoming binding request messages by responding to them.
 * If the message is not a binding request, it will be ignored.
 */
static int rtc_ice_handle_binding_request(RTCContext *rtc, char *buf, int buf_size)
{
    int ret = 0, size;
    char tid[12];

    /* Ignore if not a binding request. */
    if (!ff_rtc_ice_is_binding_request(buf, buf_size))
        return ret;

    if (buf_size < RTC_STUN_HEADER_SIZE) {
        av_log(rtc->ctx, AV_LOG_ERROR, "Invalid STUN message, expected at least %d, got %d\n",
            RTC_STUN_HEADER_SIZE, buf_size);
        return AVERROR(EINVAL);
    }

    /* Parse transaction id from binding request in buf. */
    memcpy(tid, buf + 8, 12);

    /* Build the STUN binding response. */
    ret = ff_rtc_ice_create_binding_response(rtc, tid, sizeof(tid), rtc->buf,
                                             sizeof(rtc->buf), &size);
    if (ret < 0) {
        av_log(rtc->ctx, AV_LOG_ERROR, "Failed to create STUN binding response, size=%d\n", size);
        return ret;
    }

    ret = ffurl_write(rtc->udp, rtc->buf, size);
    if (ret < 0) {
        av_log(rtc->ctx, AV_LOG_ERROR, "Failed to send STUN binding response, size=%d\n", size);
        return ret;
    }

    return 0;
}


int rtc_init(RTCContext *rtc) {

    uint32_t seed;
    int ret, ideal_pkt_size = 532;

    rtc->rtc_starttime = av_gettime_relative();

    rtc->hist = av_calloc(rtc->hist_sz, sizeof(*rtc->hist));
    if (!rtc->hist)
        return AVERROR(ENOMEM);

    rtc->hist_pool = av_calloc(rtc->hist_sz, rtc->pkt_size - RTC_DTLS_SRTP_CHECKSUM_LEN);
    if (!rtc->hist_pool)
        return AVERROR(ENOMEM);

    for (int i = 0; i < rtc->hist_sz; i++)
        rtc->hist[i].buf = rtc->hist_pool + i * (rtc->pkt_size - RTC_DTLS_SRTP_CHECKSUM_LEN);

    /**
    * Get or Generate a self-signed certificate and private key for DTLS,
    * fingerprint for SDP
    */
    ret = ff_rtc_init_certificate(rtc);
    if (ret < 0) {
        av_log(rtc->ctx, AV_LOG_ERROR, "Failed to init certificate and key\n");
        return ret;
    }

    /* Initialize the random number generator. */
    seed = av_get_random_seed();
    av_lfg_init(&rtc->rnd, seed);

    /* 64 bit tie breaker for ICE-CONTROLLING (RFC 8445 16.1) */
    ret = av_random_bytes((uint8_t *)&rtc->ice_tie_breaker, sizeof(rtc->ice_tie_breaker));
    if (ret < 0) {
        av_log(rtc->ctx, AV_LOG_ERROR, "Couldn't generate random bytes for ICE tie breaker\n");
        return ret;
    }

    rtc->audio_first_seq = av_lfg_get(&rtc->rnd) & 0x0fff;
    rtc->video_first_seq = rtc->audio_first_seq + 1;

    if (rtc->pkt_size < ideal_pkt_size)
        av_log(rtc->ctx, AV_LOG_WARNING, "pkt_size=%d(<%d) is too small, may cause packet loss\n",
               rtc->pkt_size, ideal_pkt_size);

    if ((ret = parse_codec(rtc)) < 0)
        return ret;

    if (rtc->state < RTC_STATE_INIT)
        rtc->state = RTC_STATE_INIT;

    return 0;
}

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
        av_log(rtc->ctx, AV_LOG_ERROR, "Failed to build username %s:%s, max=%zu, ret=%d\n",
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
        av_log(rtc->ctx, AV_LOG_ERROR, "Invalid transaction ID size. Expected 12, got %d\n", tid_size);
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
                                        &(rtc->dtls_fingerprint))) < 0) {
            av_log(rtc->ctx, AV_LOG_ERROR, "Failed to read DTLS certificate from cert=%s, key=%s\n",
                rtc->cert_file, rtc->key_file);
            return ret;
        }
    } else {
        /* Generate a private key to ctx->dtls_pkey and self-signed certificate. */
        if ((ret = ff_ssl_gen_key_cert(rtc->key_buf, sizeof(rtc->key_buf),
                                       rtc->cert_buf, sizeof(rtc->cert_buf),
                                       &(rtc->dtls_fingerprint))) < 0) {
            av_log(rtc->ctx, AV_LOG_ERROR, "Failed to generate DTLS private key and certificate\n");
            return ret;
        }
    }

    return ret;
}

av_cold int ff_rtc_dtls_open(RTCContext *rtc, int is_dtls_active)
{
    int ret = 0;
    AVDictionary *opts = NULL;
    char buf[256];

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
    ret = ffurl_open_whitelist(&(rtc->dtls_uc), buf, AVIO_FLAG_READ_WRITE, &rtc->ctx->interrupt_callback,
        &opts, rtc->ctx->protocol_whitelist, rtc->ctx->protocol_blacklist, NULL);
    av_dict_free(&opts);
    if (ret < 0) {
        av_log(rtc->ctx, AV_LOG_ERROR, "Failed to open DTLS url:%s\n", buf);
        goto end;
    }
    /* reuse the udp created by whip */
    ff_tls_set_external_socket(rtc->dtls_uc, rtc->udp);
end:
    return ret;
}

static int rtp_history_store(RTCContext *rtc, const uint8_t *buf, int size)
{
    uint16_t seq = AV_RB16(buf + 2);
    uint32_t pos = ((uint32_t)seq - (uint32_t)rtc->video_first_seq) % (uint32_t)rtc->hist_sz;
    RTC_RtpHistoryItem *it = &rtc->hist[pos];
    if (size > rtc->pkt_size - RTC_DTLS_SRTP_CHECKSUM_LEN)
        return AVERROR_INVALIDDATA;
    memcpy(it->buf, buf, size);
    it->size = size;
    it->seq = seq;

    rtc->hist_head = ++pos;
    return 0;
}

static const RTC_RtpHistoryItem *rtp_history_find(RTCContext *rtc, uint16_t seq)
{
    uint32_t pos = ((uint32_t)seq - (uint32_t)rtc->video_first_seq) % (uint32_t)rtc->hist_sz;
    const RTC_RtpHistoryItem *it = &rtc->hist[pos];
    return it->seq == seq ? it : NULL;
}


/**
 * Callback triggered by the RTP muxer when it creates and sends out an RTP packet.
 *
 * This function modifies the video STAP packet, removing the markers, and updating the
 * NRI of the first NALU. Additionally, it uses the corresponding SRTP context to encrypt
 * the RTP packet, where the video packet is handled by the video SRTP context.
 */
static int on_rtp_write_packet(void *opaque, const uint8_t *buf, int buf_size)
{
    int ret, cipher_size, is_rtcp, is_video;
    uint8_t payload_type;
    AVFormatContext *s = opaque;
    SRTPContext *srtp;

    /* Ignore if not RTP or RTCP packet. */
    if (!ff_rtc_is_rtp_or_rtcp(buf, buf_size))
        return 0;

    /* Only support audio, video and rtcp. */
    is_rtcp = ff_rtc_is_rtcp(buf, buf_size);
    payload_type = buf[1] & 0x7f;
    is_video = payload_type == rtc->video_payload_type;
    if (!is_rtcp && payload_type != rtc->video_payload_type && payload_type != rtc->audio_payload_type)
        return 0;

    /* Get the corresponding SRTP context. */
    srtp = is_rtcp ? &rtc->srtp_rtcp_send : (is_video? &rtc->srtp_video_send : &rtc->srtp_audio_send);

    /* Encrypt by SRTP and send out. */
    cipher_size = ff_srtp_encrypt(srtp, buf, buf_size, rtc->buf, sizeof(rtc->buf));
    if (cipher_size <= 0 || cipher_size < buf_size) {
        av_log(rtc->ctx, AV_LOG_WARNING, "Failed to encrypt packet=%dB, cipher=%dB\n", buf_size, cipher_size);
        return 0;
    }

    if (is_video) {
        ret = rtp_history_store(rtc, buf, buf_size);
        if (ret < 0)
            return ret;
    }

    ret = ffurl_write(rtc->udp, rtc->buf, cipher_size);
    if (ret < 0) {
        av_log(rtc->ctx, AV_LOG_ERROR, "Failed to write packet=%dB, ret=%d\n", cipher_size, ret);
        return ret;
    }

    return ret;
}

int rtc_setup(RTCContext *rtc)
{   
    int ret = 0;
    if ((ret = ff_rtc_udp_connect(rtc)) < 0)
        goto end;

    if ((ret = rtc_ice_dtls_handshake(rtc, 0)) < 0) // taking 0 for now , later we will take from whip
        goto end;

    if ((ret = setup_srtp(rtc)) < 0)
        goto end;

    if ((ret = create_rtp_muxer(rtc)) < 0)
        goto end;

end:
    return ret;
}

/**
 * To establish a connection with the UDP server, we utilize ICE-LITE in a Client-Server
 * mode. In this setup, FFmpeg acts as the UDP client, while the peer functions as the
 * UDP server.
 */
static int ff_rtc_udp_connect(RTCContext *rtc)
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
    av_dict_set_int(&opts, "buffer_size", rtc->ts_buffer_size, 0);

    ret = ffurl_open_whitelist(&rtc->udp, url, AVIO_FLAG_WRITE, &rtc->ctx->interrupt_callback,
        &opts, rtc->ctx->protocol_whitelist, rtc->ctx->protocol_blacklist, NULL);
    if (ret < 0) {
        av_log(rtc->ctx, AV_LOG_ERROR, "Failed to connect udp://%s:%d\n", rtc->ice_host, rtc->ice_port);
        goto end;
    }

    /* Make the socket non-blocking, set to READ and WRITE mode after connected */
    ff_socket_nonblock(ffurl_get_file_handle(rtc->udp), 1);
    rtc->udp->flags |= AVIO_FLAG_READ | AVIO_FLAG_NONBLOCK;

    if (rtc->state < RTC_STATE_UDP_CONNECTED)
        rtc->state = RTC_STATE_UDP_CONNECTED;
    rtc->rtc_udp_time = av_gettime_relative();
    av_log(rtc->ctx, AV_LOG_VERBOSE, "UDP state=%d, elapsed=%.2fms, connected to udp://%s:%d\n",
        rtc->state, ELAPSED(rtc->rtc_starttime, av_gettime_relative()), rtc->ice_host, rtc->ice_port);

end:
    av_dict_free(&opts);
    return ret;
}

int ff_rtc_ice_dtls_handshake(RTCContext *rtc, int is_dtls_active)
{
    int ret = 0, size, i;
    int64_t starttime = av_gettime_relative(), now;

    if (rtc->state < RTC_STATE_UDP_CONNECTED || !rtc->udp) {
        av_log(rtc->ctx, AV_LOG_ERROR, "UDP not connected, state=%d, udp=%p\n", rtc->state, rtc->udp);
        return AVERROR(EINVAL);
    }

    while (1) {
        if (rtc->state <= RTC_STATE_ICE_CONNECTING) {
            /* Build the STUN binding request. */
            ret = ff_rtc_ice_create_binding_request(&rtc, rtc->buf, sizeof(rtc->buf),
                                                    &size);
            if (ret < 0) {
                av_log(rtc->ctx, AV_LOG_ERROR, "Failed to create STUN binding request, size=%d\n", size);
                goto end;
            }

            ret = ffurl_write(rtc->udp, rtc->buf, size);
            if (ret < 0) {
                av_log(rtc->ctx, AV_LOG_ERROR, "Failed to send STUN binding request, size=%d\n", size);
                goto end;
            }

            if (rtc->state < RTC_STATE_ICE_CONNECTING)
                rtc->state = RTC_STATE_ICE_CONNECTING;
        }

next_packet:
        if (rtc->state >= RTC_STATE_DTLS_FINISHED)
            /* DTLS handshake is done, exit the loop. */
            break;

        now = av_gettime_relative();
        if (now - starttime >= rtc->handshake_timeout * RTC_WHIP_US_PER_MS) {
            av_log(rtc->ctx, AV_LOG_ERROR, "DTLS handshake timeout=%dms, cost=%.2fms, elapsed=%.2fms, state=%d\n",
                rtc->handshake_timeout, ELAPSED(starttime, now), ELAPSED(rtc->rtc_starttime, now), rtc->state);
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
                av_usleep(RTC_ICE_DTLS_READ_SLEEP_DURATION * RTC_WHIP_US_PER_MS);
                continue;
            }
            if (is_dtls_active)
                break;
            av_log(rtc->ctx, AV_LOG_ERROR, "Failed to read message\n");
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
            if ((ret = ice_handle_binding_request(rtc, rtc->buf, ret)) < 0)
                goto end;
            goto next_packet;
        }

        /* Handle DTLS handshake */
        if (ff_is_dtls_packet(rtc->buf, ret) || is_dtls_active) {
            rtc->rtc_ice_time = av_gettime_relative();
            /* Start consent timer when ICE selected */
            rtc->rtc_last_consent_tx_time = rtc->rtc_last_consent_rx_time = rtc->rtc_ice_time;
            rtc->state = RTC_STATE_ICE_CONNECTED;
            av_log(rtc->ctx, AV_LOG_VERBOSE, "ICE STUN ok, state=%d, url=udp://%s:%d, location=%s, username=%s:%s, res=%dB, elapsed=%.2fms\n",
                whip->state, whip->rtc.ice_host, whip->rtc.ice_port, whip->whip_resource_url ? whip->whip_resource_url : "",
                whip->rtc.ice_ufrag_remote, whip->rtc.ice_ufrag_local, ret, ELAPSED(rtc->rtc_starttime, rtc->rtc_ice_time));

            ret = ff_rtc_dtls_open(&rtc, is_dtls_active);
            if (ret < 0)
                goto end;
            ret = ffurl_handshake(rtc->dtls_uc);
            if (ret < 0) {
                rtc->state = RTC_STATE_FAILED;
                av_log(whip, AV_LOG_ERROR, "DTLS session failed\n");
                goto end;
            }
            if (!ret) {
                rtc->state = RTC_STATE_DTLS_FINISHED;
                rtc->rtc_dtls_time = av_gettime_relative();
                av_log(whip, AV_LOG_VERBOSE, "DTLS handshake is done, elapsed=%.2fms\n",
                    ELAPSED(rtc->rtc_starttime, rtc->rtc_dtls_time));
            }
            goto next_packet;
        }
    }

end:
    return ret;
}

/**
 * Establish the SRTP context using the keying material exported from DTLS.
 *
 * Create separate SRTP contexts for sending video and audio, as their sequences differ
 * and should not share a single context. Generate a single SRTP context for receiving
 * RTCP only.
 *
 * @return 0 if OK, AVERROR_xxx on error
 */
static int setup_srtp(RTCContext *rtc)
{
    int ret;
    char recv_key[RTC_DTLS_SRTP_KEY_LEN + RTC_DTLS_SRTP_SALT_LEN];
    char send_key[RTC_DTLS_SRTP_KEY_LEN + RTC_DTLS_SRTP_SALT_LEN];
    char buf[AV_BASE64_SIZE(RTC_DTLS_SRTP_KEY_LEN + RTC_DTLS_SRTP_SALT_LEN)];
    /**
     * The profile for OpenSSL's SRTP is SRTP_AES128_CM_SHA1_80, see ssl/d1_srtp.c.
     * The profile for FFmpeg's SRTP is SRTP_AES128_CM_HMAC_SHA1_80, see libavformat/srtp.c.
     */
    const char* suite = "SRTP_AES128_CM_HMAC_SHA1_80";
    // int is_dtls_active = whip->flags & WHIP_DTLS_ACTIVE; 0 for now
    int is_dtls_active = 0; // just for now
    char *cp = is_dtls_active ? send_key : recv_key;
    char *sp = is_dtls_active ? recv_key : send_key;

    ret = ff_dtls_export_materials(rtc->dtls_uc, rtc->dtls_srtp_materials, sizeof(rtc->dtls_srtp_materials));
    if (ret < 0)
        goto end;
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

    /* Setup SRTP context for outgoing packets */
    if (!av_base64_encode(buf, sizeof(buf), send_key, sizeof(send_key))) {
        av_log(rtc->ctx, AV_LOG_ERROR, "Failed to encode send key\n");
        ret = AVERROR(EIO);
        goto end;
    }

    ret = ff_srtp_set_crypto(&rtc->srtp_audio_send, suite, buf);
    if (ret < 0) {
        av_log(rtc->ctx, AV_LOG_ERROR, "Failed to set crypto for audio send\n");
        goto end;
    }

    ret = ff_srtp_set_crypto(&rtc->srtp_video_send, suite, buf);
    if (ret < 0) {
        av_log(rtc->ctx, AV_LOG_ERROR, "Failed to set crypto for video send\n");
        goto end;
    }

    ret = ff_srtp_set_crypto(&rtc->srtp_video_rtx_send, suite, buf);
    if (ret < 0) {
        av_log(rtc->ctx, AV_LOG_ERROR, "Failed to set crypto for video rtx send\n");
        goto end;
    }

    ret = ff_srtp_set_crypto(&rtc->srtp_rtcp_send, suite, buf);
    if (ret < 0) {
        av_log(rtc->ctx, AV_LOG_ERROR, "Failed to set crypto for rtcp send\n");
        goto end;
    }

    /* Setup SRTP context for incoming packets */
    if (!av_base64_encode(buf, sizeof(buf), recv_key, sizeof(recv_key))) {
        av_log(rtc->ctx, AV_LOG_ERROR, "Failed to encode recv key\n");
        ret = AVERROR(EIO);
        goto end;
    }

    ret = ff_srtp_set_crypto(&rtc->srtp_recv, suite, buf);
    if (ret < 0) {
        av_log(rtc->ctx, AV_LOG_ERROR, "Failed to set crypto for recv\n");
        goto end;
    }

    if (rtc->state < RTC_STATE_SRTP_FINISHED)
        rtc->state = RTC_STATE_SRTP_FINISHED;
    rtc->rtc_srtp_time = av_gettime_relative();
    av_log(rtc->ctx, AV_LOG_VERBOSE, "SRTP setup done, state=%d, suite=%s, key=%zuB, elapsed=%.2fms\n",
        rtc->state, suite, sizeof(send_key), ELAPSED(rtc->rtc_starttime, av_gettime_relative()));

end:
    return ret;
}

/**
 * Creates dedicated RTP muxers for each stream in the AVFormatContext to build RTP
 * packets from the encoded frames.
 *
 * The corresponding SRTP context is utilized to encrypt each stream's RTP packets. For
 * example, a video SRTP context is used for the video stream. Additionally, the
 * "on_rtp_write_packet" callback function is set as the write function for each RTP
 * muxer to send out encrypted RTP packets.
 *
 * @return 0 if OK, AVERROR_xxx on error
 */
static int create_rtp_muxer(RTCContext *rtc)
{
    int ret, i, is_video, buffer_size, max_packet_size;
    AVFormatContext *rtp_ctx = NULL;
    AVDictionary *opts = NULL;
    uint8_t *buffer = NULL;
    rtc->udp->flags |= AVIO_FLAG_NONBLOCK;


    /* The UDP buffer size, may greater than MTU. */
    buffer_size = RTC_MAX_UDP_BUFFER_SIZE;
    /* The RTP payload max size. Reserved some bytes for SRTP checksum and padding. */
    max_packet_size = rtc->pkt_size - RTC_DTLS_SRTP_CHECKSUM_LEN;

    for (i = 0; i < s->nb_streams; i++) {
        rtp_ctx = avformat_alloc_context();
        if (!rtp_ctx) {
            ret = AVERROR(ENOMEM);
            goto end;
        }

        EXTERN const FFOutputFormat ff_rtp_muxer;
        rtp_ctx->oformat = &ff_rtp_muxer.p;
        if (!avformat_new_stream(rtp_ctx, NULL)) {
            ret = AVERROR(ENOMEM);
            goto end;
        }
        /* Pass the interrupt callback on */
        rtp_ctx->interrupt_callback = s->interrupt_callback;
        /* Copy the max delay setting; the rtp muxer reads this. */
        rtp_ctx->max_delay = s->max_delay;
        /* Copy other stream parameters. */
        rtp_ctx->streams[0]->sample_aspect_ratio = s->streams[i]->sample_aspect_ratio;
        rtp_ctx->flags |= s->flags & AVFMT_FLAG_BITEXACT;
        rtp_ctx->strict_std_compliance = s->strict_std_compliance;

        /* Set the synchronized start time. */
        rtp_ctx->start_time_realtime = s->start_time_realtime;

        avcodec_parameters_copy(rtp_ctx->streams[0]->codecpar, s->streams[i]->codecpar);
        rtp_ctx->streams[0]->time_base = s->streams[i]->time_base;

        /**
         * For H.264, consistently utilize the annexb format through the Bitstream Filter (BSF);
         * therefore, we deactivate the extradata detection for the RTP muxer.
         */
        if (s->streams[i]->codecpar->codec_id == AV_CODEC_ID_H264) {
            av_freep(&rtp_ctx->streams[0]->codecpar->extradata);
            rtp_ctx->streams[0]->codecpar->extradata_size = 0;
        }

        buffer = av_malloc(buffer_size);
        if (!buffer) {
            ret = AVERROR(ENOMEM);
            goto end;
        }

        rtp_ctx->pb = avio_alloc_context(buffer, buffer_size, 1, s, NULL, on_rtp_write_packet, NULL);
        if (!rtp_ctx->pb) {
            ret = AVERROR(ENOMEM);
            goto end;
        }
        rtp_ctx->pb->max_packet_size = max_packet_size;
        rtp_ctx->pb->av_class = &ff_avio_class;

        is_video = s->streams[i]->codecpar->codec_type == AVMEDIA_TYPE_VIDEO;
        av_dict_set_int(&opts, "payload_type", is_video ? whip->rtc.video_payload_type : whip->rtc.audio_payload_type, 0);
        av_dict_set_int(&opts, "ssrc", is_video ? whip->rtc.video_ssrc : whip->rtc.audio_ssrc, 0);
        av_dict_set_int(&opts, "seq", is_video ? whip->rtc.video_first_seq : whip->rtc.audio_first_seq, 0);

        ret = avformat_write_header(rtp_ctx, &opts);
        if (ret < 0) {
            av_log(rtc->ctx, AV_LOG_ERROR, "Failed to write rtp header\n");
            goto end;
        }

        ff_format_set_url(rtp_ctx, av_strdup(s->url));
        s->streams[i]->time_base = rtp_ctx->streams[0]->time_base;
        s->streams[i]->priv_data = rtp_ctx;
        rtp_ctx = NULL;
    }

    if (whip->state < WHIP_STATE_READY)
        whip->state = WHIP_STATE_READY;
    av_log(rtc->ctx, AV_LOG_INFO, "Muxer state=%d, buffer_size=%d, max_packet_size=%d, "
                           "elapsed=%.2fms(init:%.2f,offer:%.2f,answer:%.2f,udp:%.2f,ice:%.2f,dtls:%.2f,srtp:%.2f)\n",
        whip->state, buffer_size, max_packet_size, ELAPSED(whip->whip_starttime, av_gettime_relative()),
        ELAPSED(whip->whip_starttime,   whip->whip_init_time),
        ELAPSED(whip->whip_init_time,   whip->whip_offer_time),
        ELAPSED(whip->whip_offer_time,  whip->whip_answer_time),
        ELAPSED(whip->whip_answer_time, whip->whip_udp_time),
        ELAPSED(whip->whip_udp_time,    whip->whip_ice_time),
        ELAPSED(whip->whip_ice_time,    whip->whip_dtls_time),
        ELAPSED(whip->whip_dtls_time,   whip->whip_srtp_time));

end:
    if (rtp_ctx) {
        if (!rtp_ctx->pb)
            av_freep(&buffer);
        avio_context_free(&rtp_ctx->pb);
    }
    avformat_free_context(rtp_ctx);
    av_dict_free(&opts);
    return ret;
}
