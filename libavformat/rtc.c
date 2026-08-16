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
#include "libavcodec/startcode.h"

#include "nal.h"
#include "avc.h"
#include "avio_internal.h"
#include "internal.h"
#include "network.h"
#include "tls.h"
#include "rtc.h"


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


int rtc_init(RTCContext *rtc) {

    uint32_t seed;
    int ret, ideal_pkt_size = 532;

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
end:
    av_dict_free(&opts);
    return ret;
}
