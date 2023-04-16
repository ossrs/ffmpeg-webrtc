/*
 * FLV muxer
 * Copyright (c) 2003 The FFmpeg Project
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

#include "libavutil/dict.h"
#include "libavutil/avassert.h"
#include "libavutil/mathematics.h"
#include "libavcodec/codec_desc.h"
#include "libavcodec/mpeg4audio.h"
#include "avformat.h"
#include "internal.h"
#include "mux.h"
#include "libavutil/opt.h"

typedef struct RTCContext {
    AVClass *av_class;
} RTCContext;

static int rtc_init(struct AVFormatContext *s)
{
    return 0;
}

static int rtc_write_header(struct AVFormatContext *s)
{
    return 0;
}

static int rtc_write_packet(struct AVFormatContext *s, AVPacket *pkt)
{
    return 0;
}

static int rtc_write_trailer(struct AVFormatContext *s)
{
    return 0;
}

static void rtc_deinit(struct AVFormatContext *s)
{
}

static const AVOption options[] = {
    { NULL },
};

static const AVClass rtc_muxer_class = {
    .class_name = "RTC WHIP muxer",
    .item_name  = av_default_item_name,
    .option     = NULL,
    .version    = LIBAVUTIL_VERSION_INT,
};

const FFOutputFormat ff_rtc_muxer = {
    .p.name             = "rtc",
    .p.long_name        = NULL_IF_CONFIG_SMALL("WebRTC WHIP muxer"),
    .p.audio_codec      = AV_CODEC_ID_OPUS,
    .p.video_codec      = AV_CODEC_ID_H264,
    .p.flags            = AVFMT_NOFILE,
    .p.priv_class       = &rtc_muxer_class,
    .priv_data_size     = sizeof(RTCContext),
    .init               = rtc_init,
    .write_header       = rtc_write_header,
    .write_packet       = rtc_write_packet,
    .write_trailer      = rtc_write_trailer,
    .deinit             = rtc_deinit,
};
