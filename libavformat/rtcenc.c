/*
 * WebRTC-HTTP ingestion protocol (WHIP) muxer
 * Copyright (c) 2023 The FFmpeg Project
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

#include "config.h"

#ifndef CONFIG_OPENSSL
#error "DTLS is not supported, please enable openssl"
#endif

#if CONFIG_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#if OPENSSL_VERSION_NUMBER < 0x1010102fL
#error "OpenSSL version 1.1.1b or newer is required"
#endif
#endif

#include "libavutil/dict.h"
#include "libavutil/avassert.h"
#include "libavutil/mathematics.h"
#include "libavcodec/codec_desc.h"
#include "libavcodec/mpeg4audio.h"
#include "avformat.h"
#include "internal.h"
#include "mux.h"
#include "libavutil/opt.h"
#include "libavcodec/avcodec.h"
#include "libavutil/avstring.h"
#include "url.h"
#include "libavutil/random_seed.h"
#include "avio_internal.h"
#include "libavutil/hmac.h"
#include "libavutil/crc.h"
#include "network.h"
#include "libavutil/time.h"
#include "libavutil/base64.h"
#include "srtp.h"
#include "avc.h"
#include "http.h"
#include "libavutil/bprint.h"

/**
 * Maximum size limit of a Session Description Protocol (SDP),
 * be it an offer or answer.
 */
#define MAX_SDP_SIZE 8192
/**
 * Maximum size of the buffer for sending and receiving UDP packets.
 * Please note that this size does not limit the size of the UDP packet that can be sent.
 * To set the limit for packet size, modify the `pkt_size` parameter.
 * For instance, it is possible to set the UDP buffer to 4096 to send or receive packets,
 * but please keep in mind that the `pkt_size` option limits the packet size to 1400.
 */
#define MAX_UDP_BUFFER_SIZE 4096
/*
 * Supported DTLS cipher suites for FFmpeg as a DTLS client.
 * These cipher suites are used to negotiate with DTLS servers.
 *
 * It is advisable to use a limited number of cipher suites to reduce
 * the size of DTLS UDP packets.
 */
#define DTLS_CIPHER_SUTES "ECDHE-ECDSA-AES128-GCM-SHA256"\
    ":ECDHE-RSA-AES128-GCM-SHA256"\
    ":ECDHE-ECDSA-AES128-SHA"\
    ":ECDHE-RSA-AES128-SHA"\
    ":ECDHE-ECDSA-AES256-SHA"\
    ":ECDHE-RSA-AES256-SHA"
/**
 * The size of the Secure Real-time Transport Protocol (SRTP) master key material
 * that is exported by Secure Sockets Layer (SSL) after a successful Datagram
 * Transport Layer Security (DTLS) handshake. This material consists of a key
 * of 16 bytes and a salt of 14 bytes.
 *
 * The material is exported by SSL in the following format: client_key (16 bytes) |
 * server_key (16 bytes) | client_salt (14 bytes) | server_salt (14 bytes).
 */
#define DTLS_SRTP_MASTER_KEY_LEN 30
/**
 * The maximum size of the Secure Real-time Transport Protocol (SRTP) HMAC checksum
 * and padding that is appended to the end of the packet. To calculate the maximum
 * size of the User Datagram Protocol (UDP) packet that can be sent out, subtract
 * this size from the `pkt_size`.
 */
#define DTLS_SRTP_CHECKSUM_LEN 16
/**
 * STAP-A stands for Single-Time Aggregation Packet.
 * The NALU type for STAP-A is 24 (0x18).
 */
#define NALU_TYPE_STAP_A 24

/**
 * Wait for a small timeout in milliseconds to allow for the server to process
 * the Interactive Connectivity Establishment (ICE) request. If we immediately
 * read the response after sending the request, we may receive nothing and need
 * to immediately retry. To lessen the likelihood of retries, we can send the
 * request and wait for a small amount of time for the server to process it
 * before reading the response.
 */
#define ICE_PROCESSING_TIMEOUT 10
/**
 * Wait for a short timeout in milliseconds to allow the server to process
 * the Datagram Transport Layer Security (DTLS) request. If we immediately
 * read the response after sending the request, we may receive nothing and
 * need to immediately retry. To reduce the likelihood of retries, we can
 * send the request and wait a short amount of time for the server to
 * process it before attempting to read the response.
 */
#define DTLS_PROCESSING_TIMEOUT 30
/**
 * The maximum number of retries for Datagram Transport Layer Security (DTLS) EAGAIN errors.
 * When we send a DTLS request and receive no response, we may encounter an EAGAIN error.
 * In this situation, we wait briefly and attempt to read the response again.
 * We limit the maximum number of times we retry this loop.
 */
#define DTLS_EAGAIN_RETRIES_MAX 5

/* The magic cookie for Session Traversal Utilities for NAT (STUN) messages. */
#define STUN_MAGIC_COOKIE 0x2112A442

/* STUN Attribute, comprehension-required range (0x0000-0x7FFF) */
enum StunAttr {
    STUN_ATTR_USERNAME                  = 0x0006, /// shared secret response/bind request
    STUN_ATTR_USE_CANDIDATE             = 0x0025, /// bind request
    STUN_ATTR_MESSAGE_INTEGRITY         = 0x0008, /// bind request/response
    STUN_ATTR_FINGERPRINT               = 0x8028, /// rfc5389
};

#if CONFIG_OPENSSL
typedef struct DTLSContext {
    /* For av_log to write log to this category. */
    void *log_avcl;

    /* The private key for DTLS handshake. */
    EVP_PKEY *dtls_pkey;
    /* The SSL certificate used for fingerprint in SDP and DTLS handshake. */
    X509 *dtls_cert;
    /* The fingerprint of certificate, used in SDP offer. */
    char *dtls_fingerprint;

    /**
     * This represents the material used to build the SRTP master key. It is
     * generated by DTLS and has the following layout:
     *          16B         16B         14B             14B
     *      client_key | server_key | client_salt | server_salt
     */
    uint8_t dtls_srtp_material[DTLS_SRTP_MASTER_KEY_LEN * 2];

    /* Whether the timer should be reset. */
    int dtls_should_reset_timer;
    /* Whether the DTLS is done at least for us. */
    int dtls_done_for_us;
    /* The number of packets retransmitted for DTLS. */
    int dtls_arq_packets;

    /* The UDP transport is used for delivering ICE, DTLS and SRTP packets. */
    URLContext *udp_uc;

    /* The maximum number of retries for DTLS transmission. */
    int dtls_arq_max;
    /* The step start timeout in ms for DTLS transmission. */
    int dtls_arq_timeout;
    /* The size of RTP packet, should generally be set to MTU. */
    int pkt_size;
} DTLSContext;

/**
 * Generate a self-signed certificate and private key for DTLS.
 */
static av_cold int dtls_context_init(DTLSContext *ctx)
{
    int ret = 0, serial, expire_day, i, n = 0;
    AVBPrint fingerprint;
    unsigned char md[EVP_MAX_MD_SIZE];
    const char *aor = "ffmpeg.org";
    X509_NAME* subject = NULL;
    EC_GROUP *ecgroup = NULL;
    EC_KEY* dtls_eckey = NULL;
    EVP_PKEY *dtls_pkey = NULL;
    X509 *dtls_cert = NULL;
    void *s1 = ctx->log_avcl;

    ctx->dtls_cert = dtls_cert = X509_new();
    ctx->dtls_pkey = dtls_pkey = EVP_PKEY_new();
    dtls_eckey = EC_KEY_new();

    /* To prevent a crash during cleanup, always initialize it. */
    av_bprint_init(&fingerprint, 1, MAX_SDP_SIZE);

    /* Should use the curves in ClientHello.supported_groups, for example:
     *      Supported Group: x25519 (0x001d)
     *      Supported Group: secp256r1 (0x0017)
     *      Supported Group: secp384r1 (0x0018)
     * note that secp256r1 in openssl is called NID_X9_62_prime256v1, not NID_secp256k1
     */
    ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

    if (EC_KEY_set_group(dtls_eckey, ecgroup) != 1) {
        av_log(s1, AV_LOG_ERROR, "DTLS: EC_KEY_set_group failed\n");
        ret = AVERROR(EINVAL);
        goto end;
    }
    if (EC_KEY_generate_key(dtls_eckey) != 1) {
        av_log(s1, AV_LOG_ERROR, "DTLS: EC_KEY_generate_key failed\n");
        ret = AVERROR(EINVAL);
        goto end;
    }
    if (EVP_PKEY_set1_EC_KEY(dtls_pkey, dtls_eckey) != 1) {
        av_log(s1, AV_LOG_ERROR, "DTLS: EVP_PKEY_set1_EC_KEY failed\n");
        ret = AVERROR(EINVAL);
        goto end;
    }

    /* Generate a self-signed certificate. */
    subject = X509_NAME_new();

    serial = (int)av_get_random_seed();
    if (ASN1_INTEGER_set(X509_get_serialNumber(dtls_cert), serial) != 1) {
        av_log(s1, AV_LOG_ERROR, "WHIP: Failed to set serial\n");
        ret = AVERROR(EINVAL);
        goto end;
    }

    if (X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, aor, strlen(aor), -1, 0) != 1) {
        av_log(s1, AV_LOG_ERROR, "WHIP: Failed to set CN\n");
        ret = AVERROR(EINVAL);
        goto end;
    }

    if (X509_set_issuer_name(dtls_cert, subject) != 1) {
        av_log(s1, AV_LOG_ERROR, "WHIP: Failed to set issuer\n");
        ret = AVERROR(EINVAL);
        goto end;
    }
    if (X509_set_subject_name(dtls_cert, subject) != 1) {
        av_log(s1, AV_LOG_ERROR, "WHIP: Failed to set subject name\n");
        ret = AVERROR(EINVAL);
        goto end;
    }

    expire_day = 365;
    if (!X509_gmtime_adj(X509_get_notBefore(dtls_cert), 0)) {
        av_log(s1, AV_LOG_ERROR, "WHIP: Failed to set notBefore\n");
        ret = AVERROR(EINVAL);
        goto end;
    }
    if (!X509_gmtime_adj(X509_get_notAfter(dtls_cert), 60*60*24*expire_day)) {
        av_log(s1, AV_LOG_ERROR, "WHIP: Failed to set notAfter\n");
        ret = AVERROR(EINVAL);
        goto end;
    }

    if (X509_set_version(dtls_cert, 2) != 1) {
        av_log(s1, AV_LOG_ERROR, "WHIP: Failed to set version\n");
        ret = AVERROR(EINVAL);
        goto end;
    }

    if (X509_set_pubkey(dtls_cert, dtls_pkey) != 1) {
        av_log(s1, AV_LOG_ERROR, "WHIP: Failed to set public key\n");
        ret = AVERROR(EINVAL);
        goto end;
    }

    if (!X509_sign(dtls_cert, dtls_pkey, EVP_sha1())) {
        av_log(s1, AV_LOG_ERROR, "WHIP: Failed to sign certificate\n");
        ret = AVERROR(EINVAL);
        goto end;
    }

    /* Generate the fingerpint of certficate. */
    if (X509_digest(dtls_cert, EVP_sha256(), md, &n) != 1) {
        av_log(s1, AV_LOG_ERROR, "Failed to generate fingerprint\n");
        ret = AVERROR(EIO);
        goto end;
    }
    for (i = 0; i < n; i++) {
        av_bprintf(&fingerprint, "%02X", md[i]);
        if (i < n - 1)
            av_bprintf(&fingerprint, ":");
    }
    if (!av_bprint_is_complete(&fingerprint)) {
        av_log(s1, AV_LOG_ERROR, "Fingerprint %d exceed max %d, %s\n", ret, MAX_SDP_SIZE, fingerprint.str);
        ret = AVERROR(EIO);
        goto end;
    }
    if (!fingerprint.str || !strlen(fingerprint.str)) {
        av_log(s1, AV_LOG_ERROR, "Fingerprint is empty\n");
        ret = AVERROR(EINVAL);
        goto end;
    }

    ctx->dtls_fingerprint = av_strdup(fingerprint.str);
    if (!ctx->dtls_fingerprint) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

    av_log(s1, AV_LOG_INFO, "DTLS: Fingerprint %s\n", ctx->dtls_fingerprint);

end:
    EC_KEY_free(dtls_eckey);
    EC_GROUP_free(ecgroup);
    X509_NAME_free(subject);
    av_bprint_finalize(&fingerprint, NULL);
    return ret;
}

/**
 * Cleanup the DTLS context.
 */
static av_cold void dtls_context_deinit(DTLSContext *ctx)
{
    X509_free(ctx->dtls_cert);
    EVP_PKEY_free(ctx->dtls_pkey);
    av_freep(&ctx->dtls_fingerprint);
}

/**
 * Callback function to print the OpenSSL SSL status.
 */
static void openssl_on_info(const SSL *dtls, int where, int ret)
{
    int w, r1;
    const char *method, *alert_type, *alert_desc;
    DTLSContext *ctx = (DTLSContext*)SSL_get_ex_data(dtls, 0);
    void *s1 = ctx->log_avcl;

    w = where & ~SSL_ST_MASK;
    if (w & SSL_ST_CONNECT) {
        method = "SSL_connect";
    } else if (w & SSL_ST_ACCEPT) {
        method = "SSL_accept";
    } else {
        method = "undefined";
    }

    r1 = SSL_get_error(dtls, ret);
    if (where & SSL_CB_LOOP) {
        av_log(s1, AV_LOG_VERBOSE, "DTLS: method=%s state=%s(%s), where=%d, ret=%d, r1=%d\n",
            method, SSL_state_string(dtls), SSL_state_string_long(dtls), where, ret, r1);
    } else if (where & SSL_CB_ALERT) {
        method = (where & SSL_CB_READ) ? "read":"write";

        alert_type = SSL_alert_type_string_long(ret);
        alert_desc = SSL_alert_desc_string(ret);

        if (!av_strcasecmp(alert_type, "warning") && !av_strcasecmp(alert_desc, "CN")) {
            av_log(s1, AV_LOG_WARNING, "DTLS: SSL3 alert method=%s type=%s, desc=%s(%s), where=%d, ret=%d, r1=%d\n",
                method, alert_type, alert_desc, SSL_alert_desc_string_long(ret), where, ret, r1);
        } else {
            av_log(s1, AV_LOG_ERROR, "DTLS: SSL3 alert method=%s type=%s, desc=%s(%s), where=%d, ret=%d, r1=%d\n",
                method, alert_type, alert_desc, SSL_alert_desc_string_long(ret), where, ret, r1);
        }
    } else if (where & SSL_CB_EXIT) {
        if (!ret) {
            av_log(s1, AV_LOG_WARNING, "DTLS: Fail method=%s state=%s(%s), where=%d, ret=%d, r1=%d\n",
                method, SSL_state_string(dtls), SSL_state_string_long(dtls), where, ret, r1);
        } else if (ret < 0) {
            if (r1 != SSL_ERROR_NONE && r1 != SSL_ERROR_WANT_READ && r1 != SSL_ERROR_WANT_WRITE) {
                av_log(s1, AV_LOG_ERROR, "DTLS: Error method=%s state=%s(%s), where=%d, ret=%d, r1=%d\n",
                    method, SSL_state_string(dtls), SSL_state_string_long(dtls), where, ret, r1);
            } else {
                av_log(s1, AV_LOG_VERBOSE, "DTLS: method=%s state=%s(%s), where=%d, ret=%d, r1=%d\n",
                    method, SSL_state_string(dtls), SSL_state_string_long(dtls), where, ret, r1);
            }
        }
    }
}

static unsigned int openssl_dtls_timer_cb(SSL *dtls, unsigned int previous_us)
{
    DTLSContext *ctx = (DTLSContext*)SSL_get_ex_data(dtls, 0);
    void *s1 = ctx->log_avcl;

    /* Double the timeout, note that it may be 0. */
    unsigned int timeout_us = previous_us * 2;

    /* If previous_us is 0, for example, the HelloVerifyRequest, we should respond it ASAP.
     * when got ServerHello, we should reset the timer. */
    if (!previous_us || ctx->dtls_should_reset_timer) {
        timeout_us =  ctx->dtls_arq_timeout * 1000; /* in us */
    }

    /* never exceed the max timeout. */
    timeout_us = FFMIN(timeout_us, 30 * 1000 * 1000); /* in us */

    av_log(s1, AV_LOG_VERBOSE, "DTLS: ARQ timer cb timeout=%ums, previous=%ums\n",
        timeout_us / 1000, previous_us / 1000);

    return timeout_us;
}

static void openssl_state_trace(DTLSContext *ctx, uint8_t *data, int length, int incoming, int r0, int r1)
{
    uint8_t content_type = 0;
    uint16_t size = 0;
    uint8_t handshake_type = 0;
    void *s1 = ctx->log_avcl;

    /* Change_cipher_spec(20), alert(21), handshake(22), application_data(23) */
    if (length >= 1) {
        content_type = (uint8_t)data[0];
    }

    if (length >= 13) {
        size = (uint16_t)(data[11])<<8 | (uint16_t)data[12];
    }

    if (length >= 14) {
        handshake_type = (uint8_t)data[13];
    }

    av_log(s1, AV_LOG_VERBOSE, "WHIP: DTLS state %s %s, done=%u, arq=%u, r0=%d, r1=%d, len=%u, cnt=%u, size=%u, hs=%u\n",
        "Active", (incoming? "RECV":"SEND"), ctx->dtls_done_for_us, ctx->dtls_arq_packets, r0, r1, length,
        content_type, size, handshake_type);
}

/**
 * The return value of verify_callback controls the strategy of the further verification process. If verify_callback
 * returns 0, the verification process is immediately stopped with "verification failed" state. If SSL_VERIFY_PEER is
 * set, a verification failure alert is sent to the peer and the TLS/SSL handshake is terminated. If verify_callback
 * returns 1, the verification process is continued. If verify_callback always returns 1, the TLS/SSL handshake will
 * not be terminated with respect to verification failures and the connection will be established. The calling process
 * can however retrieve the error code of the last verification error using SSL_get_verify_result(3) or by maintaining
 * its own error storage managed by verify_callback.
 */
static int openssl_verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
    /* Always OK, we don't check the certificate of client, because we allow client self-sign certificate. */
    return 1;
}

/**
 * Initializes DTLS context for client role using ECDHE.
 */
static av_cold int openssl_init_dtls_context(DTLSContext *ctx, SSL_CTX *dtls_ctx)
{
    int ret = 0;
    void *s1 = ctx->log_avcl;
    EVP_PKEY *dtls_pkey = ctx->dtls_pkey;
    X509 *dtls_cert = ctx->dtls_cert;

    /* For ECDSA, we could set the curves list. */
    if (SSL_CTX_set1_curves_list(dtls_ctx, "P-521:P-384:P-256") != 1) {
        av_log(s1, AV_LOG_ERROR, "DTLS: SSL_CTX_set1_curves_list failed\n");
        ret = AVERROR(EINVAL);
        goto end;
    }

    /* We use "ALL", while you can use "DEFAULT" means "ALL:!EXPORT:!LOW:!aNULL:!eNULL:!SSLv2" */
    if (SSL_CTX_set_cipher_list(dtls_ctx, DTLS_CIPHER_SUTES) != 1) {
        av_log(s1, AV_LOG_ERROR, "DTLS: SSL_CTX_set_cipher_list failed\n");
        ret = AVERROR(EINVAL);
        goto end;
    }
    /* Setup the certificate. */
    if (SSL_CTX_use_certificate(dtls_ctx, dtls_cert) != 1) {
        av_log(s1, AV_LOG_ERROR, "DTLS: SSL_CTX_use_certificate failed\n");
        ret = AVERROR(EINVAL);
        goto end;
    }
    if (SSL_CTX_use_PrivateKey(dtls_ctx, dtls_pkey) != 1) {
        av_log(s1, AV_LOG_ERROR, "DTLS: SSL_CTX_use_PrivateKey failed\n");
        ret = AVERROR(EINVAL);
        goto end;
    }
    /* Server will send Certificate Request. */
    SSL_CTX_set_verify(dtls_ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, openssl_verify_callback);
    /* The depth count is "level 0:peer certificate", "level 1: CA certificate",
     * "level 2: higher level CA certificate", and so on. */
    SSL_CTX_set_verify_depth(dtls_ctx, 4);
    /* Whether we should read as many input bytes as possible (for non-blocking reads) or not. */
    SSL_CTX_set_read_ahead(dtls_ctx, 1);
    /* Only support SRTP_AES128_CM_SHA1_80, please read ssl/d1_srtp.c */
    if (SSL_CTX_set_tlsext_use_srtp(dtls_ctx, "SRTP_AES128_CM_SHA1_80")) {
        av_log(s1, AV_LOG_ERROR, "DTLS: SSL_CTX_set_tlsext_use_srtp failed\n");
        ret = AVERROR(EINVAL);
        goto end;
    }

end:
    return ret;
}

/**
 * After creating a DTLS context, initialize the DTLS SSL object.
 */
static av_cold int openssl_init_dtls_ssl(DTLSContext *ctx, SSL *dtls)
{
    int ret = 0;

    /* Setup the callback for logging. */
    SSL_set_ex_data(dtls, 0, ctx);
    SSL_set_info_callback(dtls, openssl_on_info);

    /* Set dtls fragment size */
    SSL_set_options(dtls, SSL_OP_NO_QUERY_MTU);
    /* Avoid dtls negotiate failed, limit the max size of DTLS fragment. */
    SSL_set_mtu(dtls, ctx->pkt_size);

    /* Set the callback for ARQ timer. */
    DTLS_set_timer_cb(dtls, openssl_dtls_timer_cb);

    /* Setup DTLS as active, which is client role. */
    SSL_set_connect_state(dtls);
    SSL_set_max_send_fragment(dtls, ctx->pkt_size);

    return ret;
}

/**
 * Drives the SSL context by attempting to read packets to send from SSL, sending them
 * over UDP, and then reading packets from UDP to feed back to SSL.
 */
static int openssl_drive_context(DTLSContext *ctx, SSL *dtls, BIO *bio_in, BIO *bio_out, int loop)
{
    int ret, i, j, r0, r1, req_size, res_size = 0;
    uint8_t *data = NULL, req_ct = 0, req_ht = 0, res_ct = 0, res_ht = 0;
    char buf[MAX_UDP_BUFFER_SIZE];
    void *s1 = ctx->log_avcl;

    /* Drive the SSL context by state change, arq or response messages. */
    r0 = SSL_do_handshake(dtls);
    r1 = SSL_get_error(dtls, r0);

    /* Handshake successfully done */
    if (r0 == 1) {
        ctx->dtls_done_for_us = 1;
        return 0;
    }

    /* Handshake failed with fatal error */
    if (r0 < 0 && r1 != SSL_ERROR_WANT_READ) {
        av_log(s1, AV_LOG_ERROR, "DTLS: Start handshake failed, loop=%d, r0=%d, r1=%d\n", loop, r0, r1);
        return AVERROR(EIO);
    }

    /* Fast retransmit the request util got response. */
    for (i = 0; i <= ctx->dtls_arq_max && !res_size; i++) {
        req_size = BIO_get_mem_data(bio_out, (char**)&data);
        openssl_state_trace(ctx, data, req_size, 0, r0, r1);
        ret = ffurl_write(ctx->udp_uc, data, req_size);
        BIO_reset(bio_out);
        req_ct = req_size > 0 ? data[0] : 0;
        req_ht = req_size > 13 ? data[13] : 0;
        if (ret < 0) {
            av_log(s1, AV_LOG_ERROR, "DTLS: Send request failed, loop=%d, content=%d, handshake=%d, size=%d\n",
                loop, req_ct, req_ht, req_size);
            return ret;
        }

        /* Wait so that the server can process the request and no need ARQ then. */
#if DTLS_PROCESSING_TIMEOUT > 0
        av_usleep(DTLS_PROCESSING_TIMEOUT * 10000);
#endif

        for (j = 0; j <= DTLS_EAGAIN_RETRIES_MAX && !res_size; j++) {
            ret = ffurl_read(ctx->udp_uc, buf, sizeof(buf));

            /* Ignore other packets, such as ICE indication, except DTLS. */
            if (ret < 13 || buf[0] <= 19 || buf[0] >= 64)
                continue;

            /* Got DTLS response successfully. */
            if (ret > 0) {
                res_size = ret;
                ctx->dtls_should_reset_timer = 1;
                break;
            }

            /* Fatal error or timeout. */
            if (ret != AVERROR(EAGAIN)) {
                av_log(s1, AV_LOG_ERROR, "DTLS: Read response failed, loop=%d, content=%d, handshake=%d\n",
                    loop, req_ct, req_ht);
                return ret;
            }

            /* DTLSv1_handle_timeout is called when a DTLS handshake timeout expires. If no timeout
             * had expired, it returns 0. Otherwise, it retransmits the previous flight of handshake
             * messages and returns 1. If too many timeouts had expired without progress or an error
             * occurs, it returns -1. */
            r0 = DTLSv1_handle_timeout(dtls);
            if (!r0) {
                av_usleep(ctx->dtls_arq_timeout * 1000);
                continue; /* no timeout had expired. */
            }
            if (r0 != 1) {
                r1 = SSL_get_error(dtls, r0);
                av_log(s1, AV_LOG_ERROR, "DTLS: Handle timeout, loop=%d, content=%d, handshake=%d, r0=%d, r1=%d\n",
                       loop, req_ct, req_ht, r0, r1);
                return AVERROR(EIO);
            }

            ctx->dtls_arq_packets++;
            break;
        }
    }

    /* Trace the response packet, feed to SSL. */
    BIO_reset(bio_in);
    openssl_state_trace(ctx, buf, res_size, 1, r0, SSL_ERROR_NONE);
    res_ct = res_size > 0 ? buf[0]: 0;
    res_ht = res_size > 13 ? buf[13] : 0;
    if ((r0 = BIO_write(bio_in, buf, res_size)) <= 0) {
        av_log(s1, AV_LOG_ERROR, "DTLS: Feed response failed, loop=%d, content=%d, handshake=%d, size=%d, r0=%d\n",
            loop, res_ct, res_ht, res_size, r0);
        return AVERROR(EIO);
    }

    return ret;
}

/**
 * DTLS handshake with server, as a client in active mode, using openssl.
 *
 * This function initializes the SSL context as the client role using OpenSSL and
 * then performs the DTLS handshake until success. Upon successful completion, it
 * exports the SRTP material key.
 *
 * @return 0 if OK, AVERROR_xxx on error
 */
static int dtls_context_handshake(DTLSContext *ctx)
{
    int ret, loop;
    SSL_CTX *dtls_ctx = NULL;
    SSL *dtls = NULL;
    const char* dst = "EXTRACTOR-dtls_srtp";
    BIO *bio_in = NULL, *bio_out = NULL;
    void *s1 = ctx->log_avcl;

    dtls_ctx = SSL_CTX_new(DTLS_client_method());

    if (!ctx->udp_uc) {
        av_log(s1, AV_LOG_ERROR, "DTLS: No UDP context\n");
        ret = AVERROR(EIO);
        goto end;
    }

    ret = openssl_init_dtls_context(ctx, dtls_ctx);
    if (ret < 0) {
        av_log(s1, AV_LOG_ERROR, "Failed to initialize DTLS context\n");
        goto end;
    }

    /* The dtls should not be created unless the dtls_ctx has been initialized. */
    dtls = SSL_new(dtls_ctx);

    bio_in = BIO_new(BIO_s_mem());
    bio_out = BIO_new(BIO_s_mem());
    SSL_set_bio(dtls, bio_in, bio_out);

    ret = openssl_init_dtls_ssl(ctx, dtls);
    if (ret < 0) {
        av_log(s1, AV_LOG_ERROR, "Failed to initialize SSL context\n");
        goto end;
    }

    for (loop = 0; loop < 64 && !ctx->dtls_done_for_us; loop++) {
        ret = openssl_drive_context(ctx, dtls, bio_in, bio_out, loop);
        if (ret < 0) {
            av_log(s1, AV_LOG_ERROR, "Failed to drive SSL context\n");
            goto end;
        }
    }
    if (!ctx->dtls_done_for_us) {
        av_log(s1, AV_LOG_ERROR, "DTLS: Handshake failed, loop=%d\n", loop);
        ret = AVERROR(EIO);
        goto end;
    }

    /* Export SRTP master key after DTLS done */
    ret = SSL_export_keying_material(dtls, ctx->dtls_srtp_material, sizeof(ctx->dtls_srtp_material),
        dst, strlen(dst), NULL, 0, 0);
    if (!ret) {
        av_log(s1, AV_LOG_ERROR, "DTLS: SSL export key r0=%lu, ret=%d\n", ERR_get_error(), ret);
        ret = AVERROR(EIO);
        goto end;
    }

    av_log(s1, AV_LOG_INFO, "WHIP: DTLS handshake done=%d, arq=%d, srtp_material=%luB\n",
        ctx->dtls_done_for_us, ctx->dtls_arq_packets, sizeof(ctx->dtls_srtp_material));

end:
    SSL_free(dtls);
    SSL_CTX_free(dtls_ctx);
    return ret;
}

#endif

typedef struct RTCContext {
    AVClass *av_class;

    /* Parameters for the input audio and video codecs. */
    AVCodecParameters *audio_par;
    AVCodecParameters *video_par;

    /* The SPS/PPS of AVC video */
    uint8_t *avc_sps;
    int avc_sps_size;
    uint8_t *avc_pps;
    int avc_pps_size;
    /* The size of NALU in ISOM format. */
    int avc_nal_length_size;

    /* The ICE username and pwd fragment generated by the muxer. */
    char ice_ufrag_local[9];
    char ice_pwd_local[33];
    /* The SSRC of the audio and video stream, generated by the muxer. */
    uint32_t audio_ssrc;
    uint32_t video_ssrc;
    /* The PT(Payload Type) of stream, generated by the muxer. */
    uint8_t audio_payload_type;
    uint8_t video_payload_type;
    /**
     * This is the SDP offer generated by the muxer based on the codec parameters,
     * DTLS, and ICE information.
     */
    char *sdp_offer;

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

    /* The SDP answer received from the WebRTC server. */
    char *sdp_answer;
    /* The resource URL returned in the Location header of WHIP HTTP response. */
    char *whip_resource_url;

    /* The DTLS context. */
    DTLSContext dtls_ctx;

    /* The SRTP send context, to encrypt outgoing packets. */
    struct SRTPContext srtp_audio_send;
    struct SRTPContext srtp_video_send;
    struct SRTPContext srtp_rtcp_send;
    /* The SRTP receive context, to decrypt incoming packets. */
    struct SRTPContext srtp_recv;

    /* The time jitter base for audio OPUS stream. */
    int64_t audio_jitter_base;

    /* The UDP transport is used for delivering ICE, DTLS and SRTP packets. */
    URLContext *udp_uc;

    /* The maximum number of retries for ICE transmission. */
    int ice_arq_max;
    /* The step start timeout in ms for ICE transmission. */
    int ice_arq_timeout;
    /* The maximum number of retries for DTLS transmission. */
    int dtls_arq_max;
    /* The step start timeout in ms for DTLS transmission. */
    int dtls_arq_timeout;
    /* The size of RTP packet, should generally be set to MTU. */
    int pkt_size;
} RTCContext;

static int on_rtp_write_packet(void *opaque, uint8_t *buf, int buf_size);

/**
 * Initialize and check the options for the WebRTC muxer.
 */
static av_cold int whip_init(AVFormatContext *s)
{
    int ret, ideal_pkt_size = 532;
    RTCContext *rtc = s->priv_data;

    /* Use the same logging context as AV format. */
    rtc->dtls_ctx.log_avcl = s;
    rtc->dtls_ctx.dtls_arq_max = rtc->dtls_arq_max;
    rtc->dtls_ctx.dtls_arq_timeout = rtc->dtls_arq_timeout;
    rtc->dtls_ctx.pkt_size = rtc->pkt_size;

    if ((ret = dtls_context_init(&rtc->dtls_ctx)) < 0) {
        av_log(s, AV_LOG_ERROR, "WHIP: Failed to init DTLS context\n");
        return ret;
    }

    av_log(s, AV_LOG_INFO, "WHIP: Init ice_arq_max=%d, ice_arq_timeout=%d, dtls_arq_max=%d, dtls_arq_timeout=%d pkt_size=%d\n",
        rtc->ice_arq_max, rtc->ice_arq_timeout, rtc->dtls_arq_max, rtc->dtls_arq_timeout, rtc->pkt_size);

    if (rtc->pkt_size < ideal_pkt_size) {
        av_log(s, AV_LOG_WARNING, "WHIP: pkt_size=%d(<%d) is too small, may cause packet loss\n",
            rtc->pkt_size, ideal_pkt_size);
    }

    return 0;
}

/**
 * Parses the ISOM AVCC format of extradata and extracts SPS/PPS.
 *
 * This function is used to parse SPS/PPS from the extradata in ISOM AVCC format.
 * It can handle both ISOM and annexb formats but only parses data in ISOM format.
 * If the extradata is in annexb format, this function ignores it, and uses the entire
 * extradata as a sequence header with SPS/PPS. Refer to ff_isom_write_avcc.
 *
 * @param s                Pointer to the AVFormatContext
 * @param extradata        Pointer to the extradata
 * @param extradata_size   Size of the extradata
 * @returns                Returns 0 if successful or AVERROR_xxx in case of an error.
 */
static int isom_read_avcc(AVFormatContext *s, uint8_t *extradata, int  extradata_size)
{
    int ret = 0;
    uint8_t version, nal_length_size, nb_sps, nb_pps;
    AVIOContext *pb;
    RTCContext *rtc = s->priv_data;

    if (!extradata || !extradata_size)
        return 0;

    /* Not H.264 ISOM format, may be annexb etc. */
    if (extradata_size < 4 || extradata[0] != 1) {
        if (!ff_avc_find_startcode(extradata, extradata + extradata_size)) {
            av_log(s, AV_LOG_ERROR, "Format must be ISOM or annexb\n");
            return AVERROR_INVALIDDATA;
        }
        return 0;
    }

    /* Parse the SPS/PPS in ISOM format in extradata. */
    pb = avio_alloc_context(extradata, extradata_size, 0, NULL, NULL, NULL, NULL);
    if (!pb)
        return AVERROR(ENOMEM);

    version = avio_r8(pb); /* version */
    avio_r8(pb); /* avc profile */
    avio_r8(pb); /* avc profile compat */
    avio_r8(pb); /* avc level */
    nal_length_size = avio_r8(pb); /* 6 bits reserved (111111) + 2 bits nal size length - 1 (11) */
    nb_sps = avio_r8(pb); /* 3 bits reserved (111) + 5 bits number of sps */

    if (version != 1) {
        av_log(s, AV_LOG_ERROR, "Invalid version=%d\n", version);
        ret = AVERROR_INVALIDDATA;
        goto end;
    }

    rtc->avc_nal_length_size = (nal_length_size & 0x03) + 1;
    if (rtc->avc_nal_length_size == 3) {
        av_log(s, AV_LOG_ERROR, "Invalid nal length size=%d\n", rtc->avc_nal_length_size);
        ret = AVERROR_INVALIDDATA;
        goto end;
    }

    /* Read SPS */
    nb_sps &= 0x1f;
    if (nb_sps != 1 || avio_feof(pb)) {
        av_log(s, AV_LOG_ERROR, "Invalid number of sps=%d, eof=%d\n", nb_sps, avio_feof(pb));
        ret = AVERROR_INVALIDDATA;
        goto end;
    }

    rtc->avc_sps_size = avio_rb16(pb); /* sps size */
    if (rtc->avc_sps_size <= 0 || avio_feof(pb)) {
        av_log(s, AV_LOG_ERROR, "Invalid sps size=%d, eof=%d\n", rtc->avc_sps_size, avio_feof(pb));
        ret = AVERROR_INVALIDDATA;
        goto end;
    }

    rtc->avc_sps = av_malloc(rtc->avc_sps_size);
    if (!rtc->avc_sps) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

    ret = avio_read(pb, rtc->avc_sps, rtc->avc_sps_size); /* sps */
    if (ret < 0) {
        av_log(s, AV_LOG_ERROR, "Failed to read sps, size=%d\n", rtc->avc_sps_size);
        goto end;
    }

    /* Read PPS */
    nb_pps = avio_r8(pb); /* number of pps */
    if (nb_pps != 1 || avio_feof(pb)) {
        av_log(s, AV_LOG_ERROR, "Invalid number of pps=%d, eof=%d\n", nb_pps, avio_feof(pb));
        ret = AVERROR_INVALIDDATA;
        goto end;
    }

    rtc->avc_pps_size = avio_rb16(pb); /* pps size */
    if (rtc->avc_pps_size <= 0 || avio_feof(pb)) {
        av_log(s, AV_LOG_ERROR, "Invalid pps size=%d, eof=%d\n", rtc->avc_pps_size, avio_feof(pb));
        ret = AVERROR_INVALIDDATA;
        goto end;
    }

    rtc->avc_pps = av_malloc(rtc->avc_pps_size);
    if (!rtc->avc_pps) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

    ret = avio_read(pb, rtc->avc_pps, rtc->avc_pps_size); /* pps */
    if (ret < 0) {
        av_log(s, AV_LOG_ERROR, "Failed to read pps, size=%d\n", rtc->avc_pps_size);
        goto end;
    }

end:
    avio_context_free(&pb);
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
 */
static int parse_codec(AVFormatContext *s)
{
    int i, ret;
    RTCContext *rtc = s->priv_data;

    for (i = 0; i < s->nb_streams; i++) {
        AVCodecParameters *par = s->streams[i]->codecpar;
        const AVCodecDescriptor *desc = avcodec_descriptor_get(par->codec_id);
        switch (par->codec_type) {
        case AVMEDIA_TYPE_VIDEO:
            if (rtc->video_par) {
                av_log(s, AV_LOG_ERROR, "Only one video stream is supported by RTC\n");
                return AVERROR(EINVAL);
            }
            rtc->video_par = par;

            if (par->codec_id != AV_CODEC_ID_H264) {
                av_log(s, AV_LOG_ERROR, "Unsupported video codec %s by RTC, choose h264\n",
                       desc ? desc->name : "unknown");
                return AVERROR_PATCHWELCOME;
            }

            if (par->video_delay > 0) {
                av_log(s, AV_LOG_ERROR, "Unsupported B frames by RTC\n");
                return AVERROR_PATCHWELCOME;
            }

            ret = isom_read_avcc(s, par->extradata, par->extradata_size);
            if (ret < 0) {
                av_log(s, AV_LOG_ERROR, "Failed to parse SPS/PPS from extradata\n");
                return ret;
            }
            break;
        case AVMEDIA_TYPE_AUDIO:
            if (rtc->audio_par) {
                av_log(s, AV_LOG_ERROR, "Only one audio stream is supported by RTC\n");
                return AVERROR(EINVAL);
            }
            rtc->audio_par = par;

            if (par->codec_id != AV_CODEC_ID_OPUS) {
                av_log(s, AV_LOG_ERROR, "Unsupported audio codec %s by RTC, choose opus\n",
                    desc ? desc->name : "unknown");
                return AVERROR_PATCHWELCOME;
            }

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
            av_log(s, AV_LOG_ERROR, "Codec type '%s' for stream %d is not supported by RTC\n",
                   av_get_media_type_string(par->codec_type), i);
            return AVERROR_PATCHWELCOME;
        }
    }

    return 0;
}

/**
 * Generate SDP offer according to the codec parameters, DTLS and ICE information.
 * The below is an example of SDP offer:
 *
 *       v=0
 *       o=FFmpeg 4489045141692799359 2 IN IP4 127.0.0.1
 *       s=FFmpegPublishSession
 *       t=0 0
 *       a=group:BUNDLE 0 1
 *       a=extmap-allow-mixed
 *       a=msid-semantic: WMS
 *
 *       m=audio 9 UDP/TLS/RTP/SAVPF 111
 *       c=IN IP4 0.0.0.0
 *       a=ice-ufrag:a174B
 *       a=ice-pwd:wY8rJ3gNLxL3eWZs6UPOxy
 *       a=fingerprint:sha-256 EE:FE:A2:E5:6A:21:78:60:71:2C:21:DC:1A:2C:98:12:0C:E8:AD:68:07:61:1B:0E:FC:46:97:1E:BC:97:4A:54
 *       a=setup:actpass
 *       a=mid:0
 *       a=sendonly
 *       a=msid:FFmpeg audio
 *       a=rtcp-mux
 *       a=rtpmap:111 opus/48000/2
 *       a=ssrc:4267647086 cname:FFmpeg
 *       a=ssrc:4267647086 msid:FFmpeg audio
 *
 *       m=video 9 UDP/TLS/RTP/SAVPF 106
 *       c=IN IP4 0.0.0.0
 *       a=ice-ufrag:a174B
 *       a=ice-pwd:wY8rJ3gNLxL3eWZs6UPOxy
 *       a=fingerprint:sha-256 EE:FE:A2:E5:6A:21:78:60:71:2C:21:DC:1A:2C:98:12:0C:E8:AD:68:07:61:1B:0E:FC:46:97:1E:BC:97:4A:54
 *       a=setup:actpass
 *       a=mid:1
 *       a=sendonly
 *       a=msid:FFmpeg video
 *       a=rtcp-mux
 *       a=rtcp-rsize
 *       a=rtpmap:106 H264/90000
 *       a=fmtp:106 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f
 *       a=ssrc:107169110 cname:FFmpeg
 *       a=ssrc:107169110 msid:FFmpeg video
 *
 * Note that we don't use av_sdp_create to generate SDP offer because it doesn't
 * support DTLS and ICE information.
 *
 * @return 0 if OK, AVERROR_xxx on error
 */
static int generate_sdp_offer(AVFormatContext *s)
{
    int ret = 0, profile, level, profile_iop;
    AVBPrint bp;
    RTCContext *rtc = s->priv_data;

    /* To prevent a crash during cleanup, always initialize it. */
    av_bprint_init(&bp, 1, MAX_SDP_SIZE);

    if (rtc->sdp_offer) {
        av_log(s, AV_LOG_ERROR, "SDP offer is already set\n");
        ret = AVERROR(EINVAL);
        goto end;
    }

    snprintf(rtc->ice_ufrag_local, sizeof(rtc->ice_ufrag_local), "%08x",
             av_get_random_seed());
    snprintf(rtc->ice_pwd_local, sizeof(rtc->ice_pwd_local), "%08x%08x%08x%08x",
             av_get_random_seed(), av_get_random_seed(), av_get_random_seed(),
             av_get_random_seed());

    rtc->audio_ssrc = av_get_random_seed();
    rtc->video_ssrc = av_get_random_seed();

    rtc->audio_payload_type = 111;
    rtc->video_payload_type = 106;

    av_bprintf(&bp, ""
        "v=0\r\n"
        "o=FFmpeg 4489045141692799359 2 IN IP4 127.0.0.1\r\n"
        "s=FFmpegPublishSession\r\n"
        "t=0 0\r\n"
        "a=group:BUNDLE 0 1\r\n"
        "a=extmap-allow-mixed\r\n"
        "a=msid-semantic: WMS\r\n");
    if (!av_bprint_is_complete(&bp)) {
        av_log(s, AV_LOG_ERROR, "Offer %d exceed max %d, %s\n", ret, MAX_SDP_SIZE, bp.str);
        ret = AVERROR(EIO);
        goto end;
    }

    if (rtc->audio_par) {
        av_bprintf(&bp, ""
            "m=audio 9 UDP/TLS/RTP/SAVPF %u\r\n"
            "c=IN IP4 0.0.0.0\r\n"
            "a=ice-ufrag:%s\r\n"
            "a=ice-pwd:%s\r\n"
            "a=fingerprint:sha-256 %s\r\n"
            "a=setup:active\r\n"
            "a=mid:0\r\n"
            "a=sendonly\r\n"
            "a=msid:FFmpeg audio\r\n"
            "a=rtcp-mux\r\n"
            "a=rtpmap:%u opus/%d/%d\r\n"
            "a=ssrc:%u cname:FFmpeg\r\n"
            "a=ssrc:%u msid:FFmpeg audio\r\n",
            rtc->audio_payload_type,
            rtc->ice_ufrag_local,
            rtc->ice_pwd_local,
            rtc->dtls_ctx.dtls_fingerprint,
            rtc->audio_payload_type,
            rtc->audio_par->sample_rate,
            rtc->audio_par->ch_layout.nb_channels,
            rtc->audio_ssrc,
            rtc->audio_ssrc);
        if (!av_bprint_is_complete(&bp)) {
            av_log(s, AV_LOG_ERROR, "Offer %d exceed max %d, %s\n", ret, MAX_SDP_SIZE, bp.str);
            ret = AVERROR(EIO);
            goto end;
        }
    }

    if (rtc->video_par) {
        profile = rtc->video_par->profile < 0 ? 0x42 : rtc->video_par->profile;
        level = rtc->video_par->level < 0 ? 30 : rtc->video_par->level;
        profile_iop = profile & FF_PROFILE_H264_CONSTRAINED;
        av_bprintf(&bp, ""
            "m=video 9 UDP/TLS/RTP/SAVPF %u\r\n"
            "c=IN IP4 0.0.0.0\r\n"
            "a=ice-ufrag:%s\r\n"
            "a=ice-pwd:%s\r\n"
            "a=fingerprint:sha-256 %s\r\n"
            "a=setup:active\r\n"
            "a=mid:1\r\n"
            "a=sendonly\r\n"
            "a=msid:FFmpeg video\r\n"
            "a=rtcp-mux\r\n"
            "a=rtcp-rsize\r\n"
            "a=rtpmap:%u H264/90000\r\n"
            "a=fmtp:%u level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=%02x%02x%02x\r\n"
            "a=ssrc:%u cname:FFmpeg\r\n"
            "a=ssrc:%u msid:FFmpeg video\r\n",
            rtc->video_payload_type,
            rtc->ice_ufrag_local,
            rtc->ice_pwd_local,
            rtc->dtls_ctx.dtls_fingerprint,
            rtc->video_payload_type,
            rtc->video_payload_type,
            profile & (~FF_PROFILE_H264_CONSTRAINED),
            profile_iop,
            level,
            rtc->video_ssrc,
            rtc->video_ssrc);
        if (!av_bprint_is_complete(&bp)) {
            av_log(s, AV_LOG_ERROR, "Offer %d exceed max %d, %s\n", ret, MAX_SDP_SIZE, bp.str);
            ret = AVERROR(EIO);
            goto end;
        }
    }

    rtc->sdp_offer = av_strdup(bp.str);
    if (!rtc->sdp_offer) {
        ret = AVERROR(ENOMEM);
        goto end;
    }
    av_log(s, AV_LOG_VERBOSE, "WHIP: Generated offer: %s\n", rtc->sdp_offer);

end:
    av_bprint_finalize(&bp, NULL);
    return ret;
}

/**
 * Exchange SDP offer with WebRTC peer to get the answer.
 * The below is an example of SDP answer:
 *
 *       v=0
 *       o=SRS/6.0.42(Bee) 107408542208384 2 IN IP4 0.0.0.0
 *       s=SRSPublishSession
 *       t=0 0
 *       a=ice-lite
 *       a=group:BUNDLE 0 1
 *       a=msid-semantic: WMS live/show
 *
 *       m=audio 9 UDP/TLS/RTP/SAVPF 111
 *       c=IN IP4 0.0.0.0
 *       a=ice-ufrag:ex9061f9
 *       a=ice-pwd:bi8k19m9n836187b00d1gm3946234w85
 *       a=fingerprint:sha-256 68:DD:7A:95:27:BD:0A:99:F4:7A:83:21:2F:50:15:2A:1D:1F:8A:D8:96:24:42:2D:A1:83:99:BF:F1:E2:11:A2
 *       a=setup:passive
 *       a=mid:0
 *       a=recvonly
 *       a=rtcp-mux
 *       a=rtcp-rsize
 *       a=rtpmap:111 opus/48000/2
 *       a=candidate:0 1 udp 2130706431 172.20.10.7 8000 typ host generation 0
 *
 *       m=video 9 UDP/TLS/RTP/SAVPF 106
 *       c=IN IP4 0.0.0.0
 *       a=ice-ufrag:ex9061f9
 *       a=ice-pwd:bi8k19m9n836187b00d1gm3946234w85
 *       a=fingerprint:sha-256 68:DD:7A:95:27:BD:0A:99:F4:7A:83:21:2F:50:15:2A:1D:1F:8A:D8:96:24:42:2D:A1:83:99:BF:F1:E2:11:A2
 *       a=setup:passive
 *       a=mid:1
 *       a=recvonly
 *       a=rtcp-mux
 *       a=rtcp-rsize
 *       a=rtpmap:106 H264/90000
 *       a=fmtp:106 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01e
 *       a=candidate:0 1 udp 2130706431 172.20.10.7 8000 typ host generation 0
 *
 * @return 0 if OK, AVERROR_xxx on error
 */
static int exchange_sdp(AVFormatContext *s)
{
    int ret;
    char buf[MAX_URL_SIZE];
    AVBPrint bp;
    RTCContext *rtc = s->priv_data;
    /* The URL context is an HTTP transport layer for the WHIP protocol. */
    URLContext *whip_uc = NULL;

    /* To prevent a crash during cleanup, always initialize it. */
    av_bprint_init(&bp, 1, MAX_SDP_SIZE);

    ret = ffurl_alloc(&whip_uc, s->url, AVIO_FLAG_READ_WRITE, &s->interrupt_callback);
    if (ret < 0) {
        av_log(s, AV_LOG_ERROR, "Failed to alloc HTTP context: %s\n", s->url);
        goto end;
    }

    if (!rtc->sdp_offer || !strlen(rtc->sdp_offer)) {
        av_log(s, AV_LOG_ERROR, "No offer to exchange\n");
        ret = AVERROR(EINVAL);
        goto end;
    }

    snprintf(buf, sizeof(buf),
             "Cache-Control: no-cache\r\n"
             "Content-Type: application/sdp\r\n");
    av_opt_set(whip_uc->priv_data, "headers", buf, 0);
    av_opt_set(whip_uc->priv_data, "chunked_post", "0", 0);
    av_opt_set_bin(whip_uc->priv_data, "post_data", rtc->sdp_offer, (int)strlen(rtc->sdp_offer), 0);

    ret = ffurl_connect(whip_uc, NULL);
    if (ret < 0) {
        av_log(s, AV_LOG_ERROR, "Failed to request url=%s, offer: %s\n", s->url, rtc->sdp_offer);
        goto end;
    }

    if (ff_http_get_new_location(whip_uc)) {
        rtc->whip_resource_url = av_strdup(ff_http_get_new_location(whip_uc));
        if (!rtc->whip_resource_url) {
            ret = AVERROR(ENOMEM);
            goto end;
        }
    }

    while (1) {
        ret = ffurl_read(whip_uc, buf, sizeof(buf));
        if (ret == AVERROR_EOF) {
            /* Reset the error because we read all response as answer util EOF. */
            ret = 0;
            break;
        }
        if (ret <= 0) {
            av_log(s, AV_LOG_ERROR, "Failed to read response from url=%s, offer is %s, answer is %s\n",
                s->url, rtc->sdp_offer, rtc->sdp_answer);
            goto end;
        }

        av_bprintf(&bp, "%.*s", ret, buf);
        if (!av_bprint_is_complete(&bp)) {
            av_log(s, AV_LOG_ERROR, "Answer %d exceed max size %d, %s\n", ret, MAX_SDP_SIZE, bp.str);
            ret = AVERROR(EIO);
            goto end;
        }
    }

    rtc->sdp_answer = av_strdup(bp.str);
    if (!rtc->sdp_answer) {
        ret = AVERROR(ENOMEM);
        goto end;
    }
    av_log(s, AV_LOG_VERBOSE, "WHIP: Got answer: %s\n", rtc->sdp_answer);

end:
    ffurl_closep(&whip_uc);
    av_bprint_finalize(&bp, NULL);
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
static int parse_answer(AVFormatContext *s)
{
    int ret = 0;
    AVIOContext *pb;
    char line[MAX_URL_SIZE];
    const char *ptr;
    int i;
    RTCContext *rtc = s->priv_data;

    if (!rtc->sdp_answer || !strlen(rtc->sdp_answer)) {
        av_log(s, AV_LOG_ERROR, "No answer to parse\n");
        ret = AVERROR(EINVAL);
        goto end;
    }

    pb = avio_alloc_context(rtc->sdp_answer, strlen(rtc->sdp_answer), 0, NULL, NULL, NULL, NULL);
    if (!pb)
        return AVERROR(ENOMEM);

    for (i = 0; !avio_feof(pb); i++) {
        ff_get_chomp_line(pb, line, sizeof(line));
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
        } else if (av_strstart(line, "a=candidate:", &ptr) && !rtc->ice_protocol) {
            ptr = av_stristr(ptr, "udp");
            if (ptr && av_stristr(ptr, "host")) {
                char protocol[17], host[129];
                int priority, port;
                ret = sscanf(ptr, "%16s %d %128s %d typ host", protocol, &priority, host, &port);
                if (ret != 4) {
                    av_log(s, AV_LOG_ERROR, "Failed %d to parse line %d %s from %s\n",
                        ret, i, line, rtc->sdp_answer);
                    ret = AVERROR(EIO);
                    goto end;
                }

                if (av_strcasecmp(protocol, "udp")) {
                    av_log(s, AV_LOG_ERROR, "Protocol %s is not supported by RTC, choose udp, line %d %s of %s\n",
                        protocol, i, line, rtc->sdp_answer);
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
        av_log(s, AV_LOG_ERROR, "No remote ice pwd parsed from %s\n", rtc->sdp_answer);
        ret = AVERROR(EINVAL);
        goto end;
    }

    if (!rtc->ice_ufrag_remote || !strlen(rtc->ice_ufrag_remote)) {
        av_log(s, AV_LOG_ERROR, "No remote ice ufrag parsed from %s\n", rtc->sdp_answer);
        ret = AVERROR(EINVAL);
        goto end;
    }

    if (!rtc->ice_protocol || !rtc->ice_host || !rtc->ice_port) {
        av_log(s, AV_LOG_ERROR, "No ice candidate parsed from %s\n", rtc->sdp_answer);
        ret = AVERROR(EINVAL);
        goto end;
    }

    av_log(s, AV_LOG_INFO, "WHIP: SDP offer=%luB, answer=%luB, ufrag=%s, pwd=%luB, transport=%s://%s:%d\n",
        strlen(rtc->sdp_offer), strlen(rtc->sdp_answer), rtc->ice_ufrag_remote, strlen(rtc->ice_pwd_remote),
        rtc->ice_protocol, rtc->ice_host, rtc->ice_port);

end:
    avio_context_free(&pb);
    return ret;
}

/**
 * Creates and marshals an ICE binding request packet.
 *
 * This function creates and marshals an ICE binding request packet. The function only
 * generates the username attribute and does not include goog-network-info, ice-controlling,
 * use-candidate, and priority. However, some of these attributes may be added in the future.
 *
 * @param s Pointer to the AVFormatContext
 * @param buf Pointer to memory buffer to store the request packet
 * @param buf_size Size of the memory buffer
 * @param request_size Pointer to an integer that receives the size of the request packet
 * @return Returns 0 if successful or AVERROR_xxx if an error occurs.
 */
static int ice_create_request(AVFormatContext *s, uint8_t *buf, int buf_size, int *request_size)
{
    int ret, size, crc32;
    char username[128];
    AVIOContext *pb = NULL;
    AVHMAC *hmac = NULL;
    RTCContext *rtc = s->priv_data;

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
    avio_wb32(pb, av_get_random_seed()); /* transaction ID */
    avio_wb32(pb, av_get_random_seed()); /* transaction ID */
    avio_wb32(pb, av_get_random_seed()); /* transaction ID */

    /* The username is the concatenation of the two ICE ufrag */
    ret = snprintf(username, sizeof(username), "%s:%s", rtc->ice_ufrag_remote, rtc->ice_ufrag_local);
    if (ret <= 0 || ret >= sizeof(username)) {
        av_log(s, AV_LOG_ERROR, "Failed to build username %s:%s, max=%lu, ret=%d\n",
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
static int ice_create_response(AVFormatContext *s, char *tid, int tid_size, uint8_t *buf, int buf_size, int *response_size) {
    int ret = 0, size, crc32;
    AVIOContext *pb = NULL;
    AVHMAC *hmac = NULL;
    RTCContext *rtc = s->priv_data;

    if (tid_size != 12) {
        av_log(s, AV_LOG_ERROR, "Invalid transaction ID size. Expected 12, got %d\n", tid_size);
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

static int ice_is_binding_request(char *buf, int buf_size) {
    return buf_size > 1 && buf[0] == 0x00 && buf[1] == 0x01;
}

static int ice_is_binding_response(char *buf, int buf_size) {
    return buf_size > 1 && buf[0] == 0x01 && buf[1] == 0x01;
}

/**
 * This function handles incoming binding request messages by responding to them.
 * If the message is not a binding request, it will be ignored.
 */
static int ice_handle_binding_request(AVFormatContext *s, char *buf, int buf_size) {
    int ret = 0, size;
    char tid[12];
    uint8_t res_buf[MAX_UDP_BUFFER_SIZE];
    RTCContext *rtc = s->priv_data;

    /* Ignore if not a binding request. */
    if (!ice_is_binding_request(buf, buf_size))
        return ret;

    if (buf_size < 20) {
        av_log(s, AV_LOG_ERROR, "Invalid STUN message size. Expected at least 20, got %d\n", buf_size);
        return AVERROR(EINVAL);
    }

    /* Parse transaction id from binding request in buf. */
    memcpy(tid, buf + 8, 12);

    /* Build the STUN binding response. */
    ret = ice_create_response(s, tid, sizeof(tid), res_buf, sizeof(res_buf), &size);
    if (ret < 0) {
        av_log(s, AV_LOG_ERROR, "Failed to create STUN binding response, size=%d\n", size);
        return ret;
    }

    ret = ffurl_write(rtc->udp_uc, res_buf, size);
    if (ret < 0) {
        av_log(s, AV_LOG_ERROR, "Failed to send STUN binding response, size=%d\n", size);
        return ret;
    }

    return 0;
}

/**
 * Opens the UDP transport and completes the ICE handshake, using fast retransmit to
 * handle packet loss for the binding request.
 *
 * To initiate a fast retransmission of the STUN binding request during ICE, we wait only
 * for a successful local ICE process i.e., when a binding response is received from the
 * server. Since the server's binding request may not arrive, we do not always wait for it.
 * However, we will always respond to the server's binding request during ICE, DTLS or
 * RTP streaming.
 *
 * @param s Pointer to the AVFormatContext
 * @return Returns 0 if the handshake was successful or AVERROR_xxx in case of an error
 */
static int ice_handshake(AVFormatContext *s)
{
    int ret, size;
    char url[256], tmp[16];
    char req_buf[MAX_UDP_BUFFER_SIZE], res_buf[MAX_UDP_BUFFER_SIZE];
    RTCContext *rtc = s->priv_data;
    int fast_retries = rtc->ice_arq_max, timeout = rtc->ice_arq_timeout;

    /* Build UDP URL and create the UDP context as transport. */
    ff_url_join(url, sizeof(url), "udp", NULL, rtc->ice_host, rtc->ice_port, NULL);
    ret = ffurl_alloc(&rtc->udp_uc, url, AVIO_FLAG_WRITE, &s->interrupt_callback);
    if (ret < 0) {
        av_log(s, AV_LOG_ERROR, "Failed to open udp://%s:%d\n", rtc->ice_host, rtc->ice_port);
        goto end;
    }

    av_opt_set(rtc->udp_uc->priv_data, "connect", "1", 0);
    av_opt_set(rtc->udp_uc->priv_data, "fifo_size", "0", 0);
    /* Set the max packet size to the buffer size. */
    snprintf(tmp, sizeof(tmp), "%d", rtc->pkt_size);
    av_opt_set(rtc->udp_uc->priv_data, "pkt_size", tmp, 0);

    ret = ffurl_connect(rtc->udp_uc, NULL);
    if (ret < 0) {
        av_log(s, AV_LOG_ERROR, "Failed to connect udp://%s:%d\n", rtc->ice_host, rtc->ice_port);
        goto end;
    }

    /* Make the socket non-blocking, set to READ and WRITE mode after connected */
    ff_socket_nonblock(ffurl_get_file_handle(rtc->udp_uc), 1);
    rtc->udp_uc->flags |= AVIO_FLAG_READ | AVIO_FLAG_NONBLOCK;

    /* Build the STUN binding request. */
    ret = ice_create_request(s, req_buf, sizeof(req_buf), &size);
    if (ret < 0) {
        av_log(s, AV_LOG_ERROR, "Failed to create STUN binding request, size=%d\n", size);
        goto end;
    }

    /* Fast retransmit the STUN binding request. */
    while (1) {
        ret = ffurl_write(rtc->udp_uc, req_buf, size);
        if (ret < 0) {
            av_log(s, AV_LOG_ERROR, "Failed to send STUN binding request, size=%d\n", size);
            goto end;
        }

        /* Wait so that the server can process the request and no need ARQ then. */
#if ICE_PROCESSING_TIMEOUT > 0
        av_usleep(ICE_PROCESSING_TIMEOUT * 10000);
#endif

        /* Read the STUN binding response. */
        ret = ffurl_read(rtc->udp_uc, res_buf, sizeof(res_buf));
        if (ret < 0) {
            /* If max retries is 6 and start timeout is 21ms, the total timeout
             * is about 21 + 42 + 84 + 168 + 336 + 672 = 1263ms. */
            av_usleep(timeout * 1000);
            timeout *= 2;

            if (ret == AVERROR(EAGAIN) && fast_retries) {
                fast_retries--;
                continue;
            }

            av_log(s, AV_LOG_ERROR, "Failed to read STUN binding response, retries=%d\n", rtc->ice_arq_max);
            goto end;
        }

        /* If got any binding response, the fast retransmission is done. */
        if (ice_is_binding_response(res_buf, ret))
            break;

        /* When a binding request is received, it is necessary to respond immediately. */
        if (ice_is_binding_request(res_buf, ret)) {
            if ((ret = ice_handle_binding_request(s, res_buf, ret)) < 0) {
                goto end;
            }
        }
    }

    /* Wait just for a small while to get the possible binding request from server. */
    fast_retries = rtc->ice_arq_max / 2;
    timeout = rtc->ice_arq_timeout;
    while (fast_retries) {
        ret = ffurl_read(rtc->udp_uc, res_buf, sizeof(res_buf));
        if (ret < 0) {
            /* If max retries is 6 and start timeout is 21ms, the total timeout
             * is about 21 + 42 + 84 = 147ms. */
            av_usleep(timeout * 1000);
            timeout *= 2;

            if (ret == AVERROR(EAGAIN)) {
                fast_retries--;
                continue;
            }

            av_log(s, AV_LOG_ERROR, "Failed to read STUN binding request, retries=%d\n", rtc->ice_arq_max);
            goto end;
        }

        /* When a binding request is received, it is necessary to respond immediately. */
        if (ice_is_binding_request(res_buf, ret)) {
            if ((ret = ice_handle_binding_request(s, res_buf, ret)) < 0) {
                goto end;
            }
            break;
        }
    }

    av_log(s, AV_LOG_INFO, "WHIP: ICE STUN ok, url=udp://%s:%d, username=%s:%s, req=%dB, res=%dB, arq=%d\n",
        rtc->ice_host, rtc->ice_port, rtc->ice_ufrag_remote, rtc->ice_ufrag_local, size, ret,
        rtc->ice_arq_max - fast_retries);
    ret = 0;

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
static int setup_srtp(AVFormatContext *s)
{
    int ret;
    char recv_key[DTLS_SRTP_MASTER_KEY_LEN], send_key[DTLS_SRTP_MASTER_KEY_LEN];
    char buf[AV_BASE64_SIZE(DTLS_SRTP_MASTER_KEY_LEN)];
    const char* suite = "AES_CM_128_HMAC_SHA1_80";
    RTCContext *rtc = s->priv_data;

    /* As DTLS client, the send key is client master key plus salt. */
    memcpy(send_key, rtc->dtls_ctx.dtls_srtp_material, 16);
    memcpy(send_key + 16, rtc->dtls_ctx.dtls_srtp_material + 32, 14);

    /* As DTLS client, the recv key is server master key plus salt. */
    memcpy(recv_key, rtc->dtls_ctx.dtls_srtp_material + 16, 16);
    memcpy(recv_key + 16, rtc->dtls_ctx.dtls_srtp_material + 46, 14);

    /* Setup SRTP context for outgoing packets */
    if (!av_base64_encode(buf, sizeof(buf), send_key, sizeof(send_key))) {
        av_log(s, AV_LOG_ERROR, "Failed to encode send key\n");
        ret = AVERROR(EIO);
        goto end;
    }

    ret = ff_srtp_set_crypto(&rtc->srtp_audio_send, suite, buf);
    if (ret < 0) {
        av_log(s, AV_LOG_ERROR, "Failed to set crypto for audio send\n");
        goto end;
    }

    ret = ff_srtp_set_crypto(&rtc->srtp_video_send, suite, buf);
    if (ret < 0) {
        av_log(s, AV_LOG_ERROR, "Failed to set crypto for video send\n");
        goto end;
    }

    ret = ff_srtp_set_crypto(&rtc->srtp_rtcp_send, suite, buf);
    if (ret < 0) {
        av_log(s, AV_LOG_ERROR, "Failed to set crypto for rtcp send\n");
        goto end;
    }

    /* Setup SRTP context for incoming packets */
    if (!av_base64_encode(buf, sizeof(buf), recv_key, sizeof(recv_key))) {
        av_log(s, AV_LOG_ERROR, "Failed to encode recv key\n");
        ret = AVERROR(EIO);
        goto end;
    }

    ret = ff_srtp_set_crypto(&rtc->srtp_recv, suite, buf);
    if (ret < 0) {
        av_log(s, AV_LOG_ERROR, "Failed to set crypto for recv\n");
        goto end;
    }

    av_log(s, AV_LOG_INFO, "WHIP: SRTP setup done, suite=%s, key=%luB\n", suite, sizeof(send_key));

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
static int create_rtp_muxer(AVFormatContext *s)
{
    int ret, i, is_video, buffer_size, max_packet_size;
    AVFormatContext *rtp_ctx = NULL;
    AVDictionary *opts = NULL;
    uint8_t *buffer = NULL;
    char buf[64];
    RTCContext *rtc = s->priv_data;

    const AVOutputFormat *rtp_format = av_guess_format("rtp", NULL, NULL);
    if (!rtp_format) {
        av_log(s, AV_LOG_ERROR, "Failed to guess rtp muxer\n");
        ret = AVERROR(ENOSYS);
        goto end;
    }

    /* The UDP buffer size, may greater than MTU. */
    buffer_size = MAX_UDP_BUFFER_SIZE;
    /* The RTP payload max size. Reserved some bytes for SRTP checksum and padding. */
    max_packet_size = rtc->pkt_size - DTLS_SRTP_CHECKSUM_LEN;

    for (i = 0; i < s->nb_streams; i++) {
        rtp_ctx = avformat_alloc_context();
        if (!rtp_ctx) {
            ret = AVERROR(ENOMEM);
            goto end;
        }

        rtp_ctx->oformat = rtp_format;
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
        snprintf(buf, sizeof(buf), "%d", is_video? rtc->video_payload_type : rtc->audio_payload_type);
        av_dict_set(&opts, "payload_type", buf, 0);
        snprintf(buf, sizeof(buf), "%d", is_video? rtc->video_ssrc : rtc->audio_ssrc);
        av_dict_set(&opts, "ssrc", buf, 0);

        ret = avformat_write_header(rtp_ctx, &opts);
        if (ret < 0) {
            av_log(s, AV_LOG_ERROR, "Failed to write rtp header\n");
            goto end;
        }

        ff_format_set_url(rtp_ctx, av_strdup(s->url));
        s->streams[i]->time_base = rtp_ctx->streams[0]->time_base;
        s->streams[i]->priv_data = rtp_ctx;
        rtp_ctx = NULL;
    }

    av_log(s, AV_LOG_INFO, "WHIP: Create RTP muxer OK, buffer_size=%d, max_packet_size=%d\n",
        buffer_size, max_packet_size);

end:
    if (rtp_ctx)
        avio_context_free(&rtp_ctx->pb);
    avformat_free_context(rtp_ctx);
    av_dict_free(&opts);
    return ret;
}

/**
 * Callback triggered by the RTP muxer when it creates and sends out an RTP packet.
 *
 * This function modifies the video STAP packet, removing the markers, and updating the
 * NRI of the first NALU. Additionally, it uses the corresponding SRTP context to encrypt
 * the RTP packet, where the video packet is handled by the video SRTP context.
 */
static int on_rtp_write_packet(void *opaque, uint8_t *buf, int buf_size)
{
    int ret, cipher_size, is_rtcp, is_video;
    uint8_t payload_type, nalu_header;
    char cipher[MAX_UDP_BUFFER_SIZE];
    AVFormatContext *s = opaque;
    RTCContext *rtc = s->priv_data;
    struct SRTPContext *srtp;

    /* Ignore if not RTP or RTCP packet. */
    if (buf_size < 12 || (buf[0] & 0xC0) != 0x80)
        return 0;

    /* Only support audio, video and rtcp. */
    is_rtcp = buf[1] >= 192 && buf[1] <= 223;
    payload_type = buf[1] & 0x7f;
    is_video = payload_type == rtc->video_payload_type;
    if (!is_rtcp && payload_type != rtc->video_payload_type && payload_type != rtc->audio_payload_type) {
        return 0;
    }

    /**
     * For video, the STAP-A with SPS/PPS should:
     * 1. The marker bit should be 0, never be 1.
     * 2. The NRI should equal to the first NALU's.
     */
    if (is_video && buf_size > 12) {
        nalu_header = buf[12] & 0x1f;
        if (nalu_header == NALU_TYPE_STAP_A) {
            /* Reset the marker bit to 0. */
            if (buf[1] & 0x80) {
                buf[1] &= 0x7f;
            }

            /* Reset the NRI to the first NALU's NRI. */
            if (buf_size > 15 && (buf[15]&0x60) != (buf[12]&0x60)) {
                buf[12] = (buf[12]&0x80) | (buf[15]&0x60) | (buf[12]&0x1f);
            }
        }
    }

    /* Get the corresponding SRTP context. */
    srtp = is_rtcp ? &rtc->srtp_rtcp_send : (is_video? &rtc->srtp_video_send : &rtc->srtp_audio_send);

    /* Encrypt by SRTP and send out. */
    cipher_size = ff_srtp_encrypt(srtp, buf, buf_size, cipher, sizeof(cipher));
    if (cipher_size <= 0 || cipher_size < buf_size) {
        av_log(s, AV_LOG_WARNING, "Failed to encrypt packet=%dB, cipher=%dB\n", buf_size, cipher_size);
        return 0;
    }

    ret = ffurl_write(rtc->udp_uc, cipher, cipher_size);
    if (ret < 0) {
        av_log(s, AV_LOG_ERROR, "Failed to write packet=%dB, ret=%d\n", cipher_size, ret);
        return ret;
    }

    return ret;
}

/**
 * Inserts the SPS/PPS data before each IDR (Instantaneous Decoder Refresh) frame.
 *
 * The SPS/PPS is parsed from the extradata. If it's in ISOM format, the SPS/PPS is
 * multiplexed to the data field of the packet. If it's in annexb format, then the entire
 * extradata is set to the data field of the packet.
 */
static int insert_sps_pps_packet(AVFormatContext *s, AVPacket *pkt)
{
    int ret, is_idr, size, i;
    uint8_t *p;
    AVPacket* extra = NULL;
    AVStream *st = s->streams[pkt->stream_index];
    AVFormatContext *rtp_ctx = st->priv_data;
    RTCContext *rtc = s->priv_data;

    is_idr = (pkt->flags & AV_PKT_FLAG_KEY) && st->codecpar->codec_type == AVMEDIA_TYPE_VIDEO;
    if (!is_idr || !st->codecpar->extradata)
        return 0;

    extra = av_packet_alloc();
    if (!extra)
        return AVERROR(ENOMEM);

    size = !rtc->avc_nal_length_size ? st->codecpar->extradata_size :
            rtc->avc_nal_length_size * 2 + rtc->avc_sps_size + rtc->avc_pps_size;
    ret = av_new_packet(extra, size);
    if (ret < 0) {
        av_log(s, AV_LOG_ERROR, "Failed to allocate extra packet\n");
        goto end;
    }

    /* Encode SPS/PPS in annexb format. */
    if (!rtc->avc_nal_length_size) {
        memcpy(extra->data, st->codecpar->extradata, size);
    } else {
        /* Encode SPS/PPS in ISOM format. */
        p = extra->data;
        for (i = 0; i < rtc->avc_nal_length_size; i++) {
            *p++ = rtc->avc_sps_size >> (8 * (rtc->avc_nal_length_size - i - 1));
        }
        memcpy(p, rtc->avc_sps, rtc->avc_sps_size);
        p += rtc->avc_sps_size;

        /* Encode PPS in ISOM format. */
        for (i = 0; i < rtc->avc_nal_length_size; i++) {
            *p++ = rtc->avc_pps_size >> (8 * (rtc->avc_nal_length_size - i - 1));
        }
        memcpy(p, rtc->avc_pps, rtc->avc_pps_size);
        p += rtc->avc_pps_size;
    }

    /* Setup packet and feed it to chain. */
    extra->pts = pkt->pts;
    extra->dts = pkt->dts;
    extra->stream_index = pkt->stream_index;
    extra->time_base = pkt->time_base;

    ret = ff_write_chained(rtp_ctx, 0, extra, s, 0);
    if (ret < 0)
        goto end;

end:
    av_packet_free(&extra);
    return ret;
}

/**
 * RTC is connectionless, for it's based on UDP, so it check whether sesison is
 * timeout. In such case, publishers can't republish the stream util the session
 * is timeout.
 * This function is called to notify the server that the stream is ended, server
 * should expire and close the session immediately, so that publishers can republish
 * the stream quickly.
 */
static int whip_dispose(AVFormatContext *s)
{
    int ret;
    char buf[MAX_URL_SIZE];
    URLContext *whip_uc = NULL;
    RTCContext *rtc = s->priv_data;

    if (!rtc->whip_resource_url)
        return 0;

    ret = ffurl_alloc(&whip_uc, rtc->whip_resource_url, AVIO_FLAG_READ_WRITE, &s->interrupt_callback);
    if (ret < 0) {
        av_log(s, AV_LOG_ERROR, "Failed to alloc WHIP delete context: %s\n", s->url);
        goto end;
    }

    av_opt_set(whip_uc->priv_data, "chunked_post", "0", 0);
    av_opt_set(whip_uc->priv_data, "method", "DELETE", 0);
    ret = ffurl_connect(whip_uc, NULL);
    if (ret < 0) {
        av_log(s, AV_LOG_ERROR, "Failed to DELETE url=%s\n", rtc->whip_resource_url);
        goto end;
    }

    while (1) {
        ret = ffurl_read(whip_uc, buf, sizeof(buf));
        if (ret == AVERROR_EOF) {
            ret = 0;
            break;
        }
        if (ret < 0) {
            av_log(s, AV_LOG_ERROR, "Failed to read response from DELETE url=%s\n", rtc->whip_resource_url);
            goto end;
        }
    }

    av_log(s, AV_LOG_INFO, "WHIP: Dispose resource %s\n", rtc->whip_resource_url);

end:
    ffurl_closep(&whip_uc);
    return ret;
}

static av_cold int rtc_init(AVFormatContext *s)
{
    int ret;
    RTCContext *rtc = s->priv_data;

    if ((ret = whip_init(s)) < 0)
        return ret;

    if ((ret = parse_codec(s)) < 0)
        return ret;

    if ((ret = generate_sdp_offer(s)) < 0)
        return ret;

    if ((ret = exchange_sdp(s)) < 0)
        return ret;

    if ((ret = parse_answer(s)) < 0)
        return ret;

    if ((ret = ice_handshake(s)) < 0)
        return ret;

    /* Now UDP URL context is ready, setup the DTLS transport. */
    rtc->dtls_ctx.udp_uc = rtc->udp_uc;

    if ((ret = dtls_context_handshake(&rtc->dtls_ctx)) < 0)
        return ret;

    if ((ret = setup_srtp(s)) < 0)
        return ret;

    if ((ret = create_rtp_muxer(s)) < 0)
        return ret;

    return ret;
}

static int rtc_write_packet(AVFormatContext *s, AVPacket *pkt)
{
    int ret;
    RTCContext *rtc = s->priv_data;
    AVStream *st = s->streams[pkt->stream_index];
    AVFormatContext *rtp_ctx = st->priv_data;

    /* TODO: Send binding request every 1s as WebRTC heartbeat. */
    /* TODO: Receive packets from the server such as ICE binding requests, DTLS messages,
     * and RTCP like PLI requests, then respond to them.*/

    /* For audio OPUS stream, correct the timestamp. */
    if (st->codecpar->codec_type == AVMEDIA_TYPE_AUDIO) {
        pkt->dts = pkt->pts = rtc->audio_jitter_base;
        rtc->audio_jitter_base += 960;
    }

    ret = insert_sps_pps_packet(s, pkt);
    if (ret < 0) {
        av_log(s, AV_LOG_ERROR, "Failed to insert SPS/PPS packet\n");
        return ret;
    }

    ret = ff_write_chained(rtp_ctx, 0, pkt, s, 0);
    if (ret < 0) {
        if (ret == AVERROR(EINVAL)) {
            av_log(s, AV_LOG_WARNING, "Ignore failed to write packet=%dB, ret=%d\n", pkt->size, ret);
            ret = 0;
        } else {
            av_log(s, AV_LOG_ERROR, "Failed to write packet, size=%d\n", pkt->size);
        }
        return ret;
    }

    return ret;
}

static av_cold void rtc_deinit(AVFormatContext *s)
{
    int i, ret;
    RTCContext *rtc = s->priv_data;

    ret = whip_dispose(s);
    if (ret < 0)
        av_log(s, AV_LOG_WARNING, "Failed to dispose resource, ret=%d\n", ret);

    for (i = 0; i < s->nb_streams; i++) {
        AVFormatContext* rtp_ctx = s->streams[i]->priv_data;
        if (!rtp_ctx)
            continue;

        av_write_trailer(rtp_ctx);
        avio_context_free(&rtp_ctx->pb);
        avformat_free_context(rtp_ctx);
        s->streams[i]->priv_data = NULL;
    }

    av_freep(&rtc->avc_sps);
    av_freep(&rtc->avc_pps);
    av_freep(&rtc->sdp_offer);
    av_freep(&rtc->sdp_answer);
    av_freep(&rtc->whip_resource_url);
    av_freep(&rtc->ice_ufrag_remote);
    av_freep(&rtc->ice_pwd_remote);
    av_freep(&rtc->ice_protocol);
    av_freep(&rtc->ice_host);
    ffurl_closep(&rtc->udp_uc);
    ff_srtp_free(&rtc->srtp_audio_send);
    ff_srtp_free(&rtc->srtp_video_send);
    ff_srtp_free(&rtc->srtp_rtcp_send);
    ff_srtp_free(&rtc->srtp_recv);
    dtls_context_deinit(&rtc->dtls_ctx);
}

#define OFFSET(x) offsetof(RTCContext, x)
#define DEC AV_OPT_FLAG_DECODING_PARAM
static const AVOption options[] = {
    { "ice_arq_max",        "Maximum number of retransmissions for the ICE ARQ mechanism",      OFFSET(ice_arq_max),        AV_OPT_TYPE_INT,    { .i64 = 5 },       -1, INT_MAX, DEC },
    { "ice_arq_timeout",    "Start timeout in milliseconds for the ICE ARQ mechanism",          OFFSET(ice_arq_timeout),    AV_OPT_TYPE_INT,    { .i64 = 30 },      -1, INT_MAX, DEC },
    { "dtls_arq_max",       "Maximum number of retransmissions for the DTLS ARQ mechanism",     OFFSET(dtls_arq_max),       AV_OPT_TYPE_INT,    { .i64 = 5 },       -1, INT_MAX, DEC },
    { "dtls_arq_timeout",   "Start timeout in milliseconds for the DTLS ARQ mechanism",         OFFSET(dtls_arq_timeout),   AV_OPT_TYPE_INT,    { .i64 = 50 },      -1, INT_MAX, DEC },
    { "pkt_size",           "The maximum size, in bytes, of RTP packets that send out",         OFFSET(pkt_size),           AV_OPT_TYPE_INT,    { .i64 = 1500 },    -1, INT_MAX, DEC },
    { NULL },
};

static const AVClass rtc_muxer_class = {
    .class_name = "WebRTC muxer",
    .item_name  = av_default_item_name,
    .option     = options,
    .version    = LIBAVUTIL_VERSION_INT,
};

const FFOutputFormat ff_rtc_muxer = {
    .p.name             = "rtc",
    .p.long_name        = NULL_IF_CONFIG_SMALL("WHIP WebRTC muxer"),
    .p.audio_codec      = AV_CODEC_ID_OPUS,
    .p.video_codec      = AV_CODEC_ID_H264,
    .p.flags            = AVFMT_GLOBALHEADER | AVFMT_NOFILE,
    .p.priv_class       = &rtc_muxer_class,
    .priv_data_size     = sizeof(RTCContext),
    .init               = rtc_init,
    .write_packet       = rtc_write_packet,
    .deinit             = rtc_deinit,
};
