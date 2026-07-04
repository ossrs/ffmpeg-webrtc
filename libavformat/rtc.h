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
#include "srtp.h"
#include "url.h"

#define RTC_MAX_SDP_SIZE 8192

#define RTC_DTLS_SRTP_KEY_LEN 16
#define RTC_DTLS_SRTP_SALT_LEN 14
#define RTC_DTLS_SRTP_CHECKSUM_LEN 16
#define RTC_DTLS_SRTP_MATERIALS_LEN ((RTC_DTLS_SRTP_KEY_LEN + RTC_DTLS_SRTP_SALT_LEN) * 2)

#define RTC_STUN_HEADER_SIZE 20
#define RTC_RTP_HEADER_SIZE 12

#define RTC_RTCP_PT_START 192
#define RTC_RTCP_PT_END   223

typedef struct RTCICEContext {
    AVLFG *rnd;
    const char *local_ufrag;
    const char *local_pwd;
    const char *remote_ufrag;
    const char *remote_pwd;
    uint64_t tie_breaker;
} RTCICEContext;

typedef struct RTCSDPConnectionInfo {
    int is_ice_lite;
    char *ice_ufrag;
    char *ice_pwd;
    char *fingerprint;
    char *candidate_protocol;
    char *candidate_host;
    int candidate_port;
} RTCSDPConnectionInfo;

int ff_rtc_ice_create_binding_request(void *logctx, RTCICEContext *ice,
                                      uint8_t *buf, int buf_size,
                                      int *request_size);
int ff_rtc_ice_create_binding_response(void *logctx, RTCICEContext *ice,
                                       const uint8_t *tid, int tid_size,
                                       uint8_t *buf, int buf_size,
                                       int *response_size);
int ff_rtc_ice_is_binding_request(const uint8_t *buf, int size);
int ff_rtc_ice_is_binding_response(const uint8_t *buf, int size);

int ff_rtc_is_rtp_or_rtcp(const uint8_t *buf, int size);
int ff_rtc_is_rtcp(const uint8_t *buf, int size);

int ff_rtc_parse_sdp_connection_info(void *logctx, const char *sdp,
                                     RTCSDPConnectionInfo *info);
void ff_rtc_free_sdp_connection_info(RTCSDPConnectionInfo *info);

int ff_rtc_init_certificate(void *logctx, const char *key_file,
                            const char *cert_file, char *key_buf,
                            size_t key_buf_size, char *cert_buf,
                            size_t cert_buf_size, char **fingerprint);
int ff_rtc_dtls_open(AVFormatContext *s, URLContext **dtls_uc, URLContext *udp,
                     const char *host, int port, int mtu,
                     const char *cert_file, const char *key_file,
                     const char *cert_buf, const char *key_buf,
                     int is_dtls_active);
int ff_rtc_srtp_setup_from_dtls(void *logctx, URLContext *dtls_uc,
                                int is_dtls_active,
                                SRTPContext **send_ctx, int nb_send_ctx,
                                SRTPContext *recv_ctx,
                                uint8_t *materials, size_t materials_size);

#endif /* AVFORMAT_RTC_H */
