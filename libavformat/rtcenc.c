/*
 * WebRTC muxer
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

typedef struct RTCContext {
    AVClass *av_class;

    /* Input audio and video codec parameters */
    AVCodecParameters *audio_par;
    AVCodecParameters *video_par;
} RTCContext;

/**
 * Only support video(h264) and audio(opus) for now. Note that only baseline
 * and constrained baseline of h264 are supported.
 */
static int check_codec(AVFormatContext *s)
{
    int i;
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
                return AVERROR(EINVAL);
            }
            if ((par->profile & ~FF_PROFILE_H264_CONSTRAINED) != FF_PROFILE_H264_BASELINE) {
                av_log(s, AV_LOG_ERROR, "Profile %d of stream %d is not baseline, currently unsupported by RTC\n",
                       par->profile, i);
                return AVERROR(EINVAL);
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
                return AVERROR(EINVAL);
            }

            if (par->ch_layout.nb_channels != 2) {
                av_log(s, AV_LOG_ERROR, "Unsupported audio channels %d by RTC, choose stereo\n",
                    par->ch_layout.nb_channels);
                return AVERROR(EINVAL);
            }

            if (par->sample_rate != 48000) {
                av_log(s, AV_LOG_ERROR, "Unsupported audio sample rate %d by RTC, choose 48000\n", par->sample_rate);
                return AVERROR(EINVAL);
            }
            break;
        default:
            av_log(s, AV_LOG_ERROR, "Codec type '%s' for stream %d is not supported by RTC\n",
                   av_get_media_type_string(par->codec_type), i);
            return AVERROR(EINVAL);
        }
    }

    return 0;
}

static int rtc_init(AVFormatContext *s)
{
    int ret;

    if ((ret = check_codec(s)) < 0)
        return ret;

    return 0;
}

static int rtc_write_header(AVFormatContext *s)
{
    return 0;
}

static int rtc_write_packet(AVFormatContext *s, AVPacket *pkt)
{
    return 0;
}

static int rtc_write_trailer(AVFormatContext *s)
{
    return 0;
}

static void rtc_deinit(AVFormatContext *s)
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
