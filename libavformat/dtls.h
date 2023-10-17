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

#include "avformat.h"

/**
 * The size of the Secure Real-time Transport Protocol (SRTP) master key material
 * that is exported by Secure Sockets Layer (SSL) after a successful Datagram
 * Transport Layer Security (DTLS) handshake. This material consists of a key
 * of 16 bytes and a salt of 14 bytes.
 */
#define DTLS_SRTP_KEY_LEN 16
#define DTLS_SRTP_SALT_LEN 14
/**
 * The maximum size of the Secure Real-time Transport Protocol (SRTP) HMAC checksum
 * and padding that is appended to the end of the packet. To calculate the maximum
 * size of the User Datagram Protocol (UDP) packet that can be sent out, subtract
 * this size from the `pkt_size`.
 */
#define DTLS_SRTP_CHECKSUM_LEN 16
/* DTLS init state. */
#define DTLS_STATE_NONE 0
/* Whether DTLS handshake is finished. */
#define DTLS_STATE_FINISHED 1
/* Whether DTLS session is closed. */
#define DTLS_STATE_CLOSED 2
/* Whether DTLS handshake is failed. */
#define DTLS_STATE_FAILED 3
typedef int (*dtls_fn_on_state)(void *ctx, void *opaque, int state, const char* type, const char* desc);
typedef int (*dtls_fn_on_write)(void *ctx, void *opaque, char* data, int size);

void* dtls_context_new(AVClass *av_class, void *opaque, int pkt_size, dtls_fn_on_state on_state, dtls_fn_on_write on_write, const char* cert_file, const char* key_file);
av_cold int dtls_context_init(AVFormatContext *s, void *ctx);
int dtls_context_start(void *ctx);
int dtls_context_write(void *ctx, char* buf, int size);
av_cold void dtls_context_deinit(void *ctx);

int dtls_can_handle_packet(uint8_t *b, int size);
char* dtls_get_fingerprint(void *ctx);
uint8_t* dtls_get_srtp_client_key(void *ctx);
uint8_t* dtls_get_srtp_server_key(void *ctx);
uint8_t* dtls_get_srtp_client_salt(void *ctx);
uint8_t* dtls_get_srtp_server_salt(void *ctx);

