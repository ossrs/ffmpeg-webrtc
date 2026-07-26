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

#include "libavutil/crc.h"
#include "libavutil/hmac.h"
#include "libavutil/intreadwrite.h"
#include "libavutil/avstring.h"

#include "avio_internal.h"
#include "internal.h"
#include "network.h"
#include "rtc.h"
#include "tls.h"

#define STUN_MAGIC_COOKIE 0x2112A442
#define STUN_HOST_CANDIDATE_PRIORITY (126 << 24 | 65535 << 8 | 255)

enum STUNAttr {
    STUN_ATTR_USERNAME          = 0x0006,
    STUN_ATTR_PRIORITY          = 0x0024,
    STUN_ATTR_USE_CANDIDATE     = 0x0025,
    STUN_ATTR_MESSAGE_INTEGRITY = 0x0008,
    STUN_ATTR_FINGERPRINT       = 0x8028,
    STUN_ATTR_ICE_CONTROLLING   = 0x802A,
};

int ff_rtc_ice_create_binding_request(void *logctx, RTCICEContext *ice,
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

    avio_wb16(pb, 0x0001);
    avio_wb16(pb, 0);
    avio_wb32(pb, STUN_MAGIC_COOKIE);
    avio_wb32(pb, av_lfg_get(ice->rnd));
    avio_wb32(pb, av_lfg_get(ice->rnd));
    avio_wb32(pb, av_lfg_get(ice->rnd));

    ret = snprintf(username, sizeof(username), "%s:%s",
                   ice->remote_ufrag, ice->local_ufrag);
    if (ret <= 0 || ret >= sizeof(username)) {
        av_log(logctx, AV_LOG_ERROR, "Failed to build username %s:%s, max=%zu, ret=%d\n",
               ice->remote_ufrag, ice->local_ufrag, sizeof(username), ret);
        ret = AVERROR(EIO);
        goto end;
    }

    avio_wb16(pb, STUN_ATTR_USERNAME);
    avio_wb16(pb, ret);
    avio_write(pb, username, ret);
    ffio_fill(pb, 0, (4 - (ret % 4)) % 4);

    avio_wb16(pb, STUN_ATTR_USE_CANDIDATE);
    avio_wb16(pb, 0);

    avio_wb16(pb, STUN_ATTR_PRIORITY);
    avio_wb16(pb, 4);
    avio_wb32(pb, STUN_HOST_CANDIDATE_PRIORITY);

    avio_wb16(pb, STUN_ATTR_ICE_CONTROLLING);
    avio_wb16(pb, 8);
    avio_wb64(pb, ice->tie_breaker);

    avio_wb16(pb, STUN_ATTR_MESSAGE_INTEGRITY);
    avio_wb16(pb, 20);
    ffio_fill(pb, 0, 20);
    size = avio_tell(pb);
    buf[2] = (size - 20) >> 8;
    buf[3] = (size - 20) & 0xFF;
    av_hmac_init(hmac, ice->remote_pwd, strlen(ice->remote_pwd));
    av_hmac_update(hmac, buf, size - 24);
    av_hmac_final(hmac, buf + size - 20, 20);

    avio_wb16(pb, STUN_ATTR_FINGERPRINT);
    avio_wb16(pb, 4);
    ffio_fill(pb, 0, 4);
    size = avio_tell(pb);
    buf[2] = (size - 20) >> 8;
    buf[3] = (size - 20) & 0xFF;
    crc32 = av_crc(av_crc_get_table(AV_CRC_32_IEEE_LE), 0xFFFFFFFF,
                   buf, size - 8) ^ 0xFFFFFFFF;
    avio_skip(pb, -4);
    avio_wb32(pb, crc32 ^ 0x5354554E);

    *request_size = size;

end:
    avio_context_free(&pb);
    av_hmac_free(hmac);
    return ret;
}

int ff_rtc_ice_create_binding_response(void *logctx, RTCICEContext *ice,
                                       const uint8_t *tid, int tid_size,
                                       uint8_t *buf, int buf_size,
                                       int *response_size)
{
    int ret = 0, size, crc32;
    AVIOContext *pb = NULL;
    AVHMAC *hmac = NULL;

    if (tid_size != 12) {
        av_log(logctx, AV_LOG_ERROR, "Invalid transaction ID size. Expected 12, got %d\n",
               tid_size);
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

    avio_wb16(pb, 0x0101);
    avio_wb16(pb, 0);
    avio_wb32(pb, STUN_MAGIC_COOKIE);
    avio_write(pb, tid, tid_size);

    avio_wb16(pb, STUN_ATTR_MESSAGE_INTEGRITY);
    avio_wb16(pb, 20);
    ffio_fill(pb, 0, 20);
    size = avio_tell(pb);
    buf[2] = (size - 20) >> 8;
    buf[3] = (size - 20) & 0xFF;
    av_hmac_init(hmac, ice->local_pwd, strlen(ice->local_pwd));
    av_hmac_update(hmac, buf, size - 24);
    av_hmac_final(hmac, buf + size - 20, 20);

    avio_wb16(pb, STUN_ATTR_FINGERPRINT);
    avio_wb16(pb, 4);
    ffio_fill(pb, 0, 4);
    size = avio_tell(pb);
    buf[2] = (size - 20) >> 8;
    buf[3] = (size - 20) & 0xFF;
    crc32 = av_crc(av_crc_get_table(AV_CRC_32_IEEE_LE), 0xFFFFFFFF,
                   buf, size - 8) ^ 0xFFFFFFFF;
    avio_skip(pb, -4);
    avio_wb32(pb, crc32 ^ 0x5354554E);

    *response_size = size;

end:
    avio_context_free(&pb);
    av_hmac_free(hmac);
    return ret;
}

int ff_rtc_ice_is_binding_request(const uint8_t *buf, int size)
{
    return size >= RTC_STUN_HEADER_SIZE && AV_RB16(buf) == 0x0001;
}

int ff_rtc_ice_is_binding_response(const uint8_t *buf, int size)
{
    return size >= RTC_STUN_HEADER_SIZE && AV_RB16(buf) == 0x0101;
}

int ff_rtc_is_rtp_or_rtcp(const uint8_t *buf, int size)
{
    return size >= RTC_RTP_HEADER_SIZE && (buf[0] & 0xC0) == 0x80;
}

int ff_rtc_is_rtcp(const uint8_t *buf, int size)
{
    return size >= RTC_RTP_HEADER_SIZE &&
           buf[1] >= RTC_RTCP_PT_START && buf[1] <= RTC_RTCP_PT_END;
}

int ff_rtc_init_certificate(void *logctx, const char *key_file,
                            const char *cert_file, char *key_buf,
                            size_t key_buf_size, char *cert_buf,
                            size_t cert_buf_size, char **fingerprint)
{
    int ret;

    if (cert_file && key_file) {
        ret = ff_ssl_read_key_cert((char *)key_file, (char *)cert_file,
                                   key_buf, key_buf_size, cert_buf,
                                   cert_buf_size, fingerprint);
        if (ret < 0)
            av_log(logctx, AV_LOG_ERROR,
                   "Failed to read DTLS certificate from cert=%s, key=%s\n",
                   cert_file, key_file);
    } else {
        ret = ff_ssl_gen_key_cert(key_buf, key_buf_size, cert_buf,
                                  cert_buf_size, fingerprint);
        if (ret < 0)
            av_log(logctx, AV_LOG_ERROR,
                   "Failed to generate DTLS private key and certificate\n");
    }

    return ret;
}

int ff_rtc_dtls_open(void *logctx, AVFormatContext *s, URLContext **dtls_uc,
                     URLContext *udp, const char *host, int port, int mtu,
                     const char *cert_file, const char *key_file,
                     const char *cert_buf, const char *key_buf,
                     int is_dtls_active)
{
    int ret;
    AVDictionary *opts = NULL;
    char url[256];

    ff_url_join(url, sizeof(url), "dtls", NULL, host, port, NULL);
    av_dict_set_int(&opts, "mtu", mtu, 0);
    if (cert_file)
        av_dict_set(&opts, "cert_file", cert_file, 0);
    else
        av_dict_set(&opts, "cert_pem", cert_buf, 0);

    if (key_file)
        av_dict_set(&opts, "key_file", key_file, 0);
    else
        av_dict_set(&opts, "key_pem", key_buf, 0);

    av_dict_set_int(&opts, "external_sock", 1, 0);
    av_dict_set_int(&opts, "use_srtp", 1, 0);
    av_dict_set_int(&opts, "listen", is_dtls_active ? 0 : 1, 0);
    // Do not verify CA
    av_dict_set_int(&opts, "verify", 0, 0);

    ret = ffurl_open_whitelist(dtls_uc, url, AVIO_FLAG_READ_WRITE,
                               &s->interrupt_callback, &opts,
                               s->protocol_whitelist, s->protocol_blacklist,
                               NULL);
    av_dict_free(&opts);
    if (ret < 0) {
        av_log(logctx, AV_LOG_ERROR, "Failed to open DTLS url:%s\n", url);
        return ret;
    }

    ff_tls_set_external_socket(*dtls_uc, udp);
    return 0;
}
