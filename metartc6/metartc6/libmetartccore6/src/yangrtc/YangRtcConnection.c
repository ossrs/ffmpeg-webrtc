//
// Copyright (c) 2019-2022 yanggaofeng
//
#include <yangice/YangRtcSocket.h>
#include <yangice/YangRtcStun.h>

#include <yangrtc/YangRtcRtcp.h>
#include <yangrtc/YangPushH264.h>
#include <yangrtc/YangPushH265.h>
//#include <yangrtc/YangBandwidth.h>

#include <yangrtc/YangPushStream.h>
#include <yangrtp/YangRtpConstant.h>
#include <yangrtp/YangRtcpCompound.h>
#include <yangrtc/YangRtcConnection.h>

#include <yangutil/sys/YangLog.h>
#include <yangutil/yangavctype.h>
#include <yangutil/sys/YangSsrc.h>
#include <yangutil/sys/YangSRtp.h>

#include <yangsdp/YangSdp.h>



void g_session_receive(char *data, int32_t nb_data, void *user) {
	if (user == NULL)		return;
	YangRtcConnection *conn = (YangRtcConnection*) user;
	conn->receive(conn->session,data,nb_data);

}

void yang_rtcconn_startStunTimer(YangRtcSession *session);

void g_yang_startStunTimer(void *user) {
	if (user == NULL)		return;
	YangRtcConnection *conn = (YangRtcConnection*) user;
	yang_rtcconn_startStunTimer(conn->session);

}

static void yang_onConnectionStateChange(YangRtcSession *session,YangRtcConnectionState state){
	if(session->context.streamConfig&&session->context.streamConfig->iceCallback.onConnectionStateChange){
						session->context.streamConfig->iceCallback.onConnectionStateChange(
								session->context.streamConfig->iceCallback.context,
								session->context.streamConfig->uid,
								state);
	}
}

void g_yang_doTask(int32_t taskId, void *user) {
	if (user == NULL)	return;
	YangRtcSession *session = (YangRtcSession*) user;
	if (!session->isServer && session->isSendStun && taskId == 1) {

		if (session->context.stun.data&& session->context.stun.nb > 0) {
			if(session->context.sock->write(&session->context.sock->session,session->context.stun.data, session->context.stun.nb)!=Yang_Ok){
				yang_error("send stun fail!");
			}
			if(session->context.state==Yang_Conn_State_New) {
				session->context.state=Yang_Conn_State_Connecting;
				yang_onConnectionStateChange(session,Yang_Conn_State_Connecting);
			}
		}

	}
	if(session->context.state!=Yang_Conn_State_Connected) return;

	if(session->push){
			if (taskId == 1) {
				if (session->push->send_rtcp_sr(&session->context,session->push->pubStream))		yang_error("send rtcp sr Error ");

			}
		}


}



void yang_rtcconn_init(YangRtcSession *session, YangStreamOptType role) {
	if (session == NULL)	return;

	session->codec =(YangVideoCodec) session->context.avinfo->video.videoEncoderType;
	session->isSendDtls = 0;

	session->sessionTimeout=session->context.avinfo->rtc.sessionTimeout;
    if (role == Yang_Stream_Publish || role==Yang_Stream_Both)  {
#if Yang_Enable_RTC_Audio
    	if(session->pushAudio==NULL){
    		session->pushAudio=(YangPushAudio*) yang_calloc(1,sizeof(YangPushAudio));
    	}
#endif
#if Yang_Enable_RTC_Video

    	session->pushH264 = NULL;
        if (session->codec == Yang_VED_264) {
            session->pushH264 = (YangPushH264*) yang_calloc(1,sizeof(YangPushH264));
        }
	#if	Yang_Enable_H265_Encoding
        session->pushH265 = NULL;
        if (session->codec == Yang_VED_265) {
            session->pushH265 = (YangPushH265*) yang_calloc(1,sizeof(YangPushH265));
        }
	#endif


#endif
    }
	//  session->20ms
	session->tm_1s = (YangCTimer*) yang_calloc(1, sizeof(YangCTimer));
	yang_create_timer(session->tm_1s, session, 1, 1000);
	session->tm_1s->doTask = g_yang_doTask;

	session->startRecv = 0;
	session->isSendStun = yangfalse;


	yang_create_rtcdtls(session->context.dtls,session->isServer);
	session->context.dtls->session.sslCallback=&session->context.streamConfig->sslCallback;
	session->context.dtls->session.uid=session->context.streamConfig->uid;





	if (role == Yang_Stream_Publish || role==Yang_Stream_Both)  {

#if Yang_Enable_RTC_Video
		if(session->pushVideoRtpBuffer == NULL) {
			session->pushVideoRtpBuffer = (YangRtpBuffer*) yang_calloc(1,sizeof(YangRtpBuffer));
			yang_create_rtpBuffer(session->pushVideoRtpBuffer, 1400, kRtpPacketSize);
		}
#endif
#if Yang_Enable_RTC_Audio
		if(session->pushAudio){
			if(session->pushAudioRtpBuffer == NULL) {
					session->pushAudioRtpBuffer = (YangRtpBuffer*) yang_calloc(1,sizeof(YangRtpBuffer));
					yang_create_rtpBuffer(session->pushAudioRtpBuffer, 100, kRtpPacketSize);
			}
			yang_create_pushAudio(session->pushAudio, session->pushAudioRtpBuffer);
		}
#endif

#if Yang_Enable_RTC_Video
		if (session->pushH264) {
			yang_create_pushH264(session->pushH264, session->pushVideoRtpBuffer);
		}
	#if	Yang_Enable_H265_Encoding
		if (session->pushH265) {
			yang_create_pushH265(session->pushH265,  session->pushVideoRtpBuffer);
		}
	#endif

#endif
		if (session->push == NULL) {
			session->push = (YangRtcPush*) yang_calloc(1,sizeof(YangRtcPush));
			yang_create_rtcpush(session->push,session->context.audioSsrc, session->context.videoSsrc);
		}
	}

	#if Yang_Enable_Datachannel
	if(session->usingDatachannel){
		if(session->datachannel==NULL){
			session->datachannel=(YangDatachannel*)yang_calloc(sizeof(YangDatachannel),1);
			yang_create_datachannel(session->datachannel,&session->context);
		}
	}
	#endif

	session->activeState = yangtrue;
}

int32_t yang_rtcconn_on_rtcp_feedback_twcc(YangRtcSession *session,YangRtcpCommon *rtcp) {
#if Yang_Enable_TWCC
	session->context.twcc.decode(&session->context.twcc.session,rtcp);
#endif
	return Yang_Ok;
}

int32_t yang_rtcconn_on_rtcp_feedback_remb(YangRtcSession *session,	YangRtcpCommon *rtcp) {

	return Yang_Ok;
}

void yang_rtcconn_do_request_keyframe(YangRtcSession *session, uint32_t ssrc) {
	if (session->context.streamConfig&&session->context.streamConfig->rtcCallback.sendRequest)
		session->context.streamConfig->rtcCallback.sendRequest(session->context.streamConfig->rtcCallback.context,session->context.streamConfig->uid, ssrc, Yang_Req_Sendkeyframe);

}

int32_t yang_rtcconn_dispatch_rtcp(YangRtcSession *session,YangRtcpCommon *rtcp) {
	int32_t err = Yang_Ok;
	uint16_t rtcpType = rtcp->header.type;
	// For TWCC packet.
	if (YangRtcpType_rtpfb == rtcpType && 15 == rtcp->header.rc) {
		return yang_rtcconn_on_rtcp_feedback_twcc(session, rtcp);
	}

	// For REMB packet.
	if (YangRtcpType_psfb == rtcpType) {

		if (15 == rtcp->header.rc) {
			return yang_rtcconn_on_rtcp_feedback_remb(session, rtcp);
		}
	}

	// Ignore special packet.
	if (YangRtcpType_rr == rtcpType) {
		if (rtcp->rb->ssrc == 0) {
			return err;
		}
	}

	if (session->push	&& Yang_Ok	!= (err = session->push->on_rtcp(&session->context,session->push->pubStream, rtcp))) {
		return yang_error_wrap(err, "handle publish rtcp");
	}


	return err;
}

void yang_rtcconn_setSsrc(YangRtcSession *session, uint32_t audioSsrc,
		uint32_t videoSsrc) {
	if(session==NULL) return;
#if Yang_Enable_RTC_Audio
	if(session->pushAudio)
		session->pushAudio->push->audioSsrc=audioSsrc;
#endif
#if Yang_Enable_RTC_Video
	if (session->pushH264)
			session->pushH264->push->videoSsrc = videoSsrc;
	#if	Yang_Enable_H265_Encoding
	if (session->pushH265)
		session->pushH265->push->videoSsrc = videoSsrc;
	#endif


#endif



}

void yang_rtcconn_startStunTimer(YangRtcSession *session) {

	if (session->tm_1s&&!session->tm_1s->isStart)
		yang_timer_start(session->tm_1s);
	session->isSendStun = yangtrue;
}

void yang_rtcconn_startTimers(YangRtcSession *session) {
	if (session->tm_1s&&!session->tm_1s->isStart)		yang_timer_start(session->tm_1s);


}

int32_t yang_rtcconn_on_rtcp(YangRtcSession *session, char *data,int32_t nb_data) {
	int32_t err = Yang_Ok;
	int32_t nb_unprotected_buf = nb_data;

	if ((err = yang_dec_rtcp(&session->context.srtp, data, &nb_unprotected_buf))!= Yang_Ok) {
		if (err == srtp_err_status_replay_fail)	return Yang_Ok;
		return yang_error_wrap(err, "rtcp unprotect");
	}

	char *unprotected_buf = data;
	YangBuffer buffer;
	yang_init_buffer(&buffer, unprotected_buf, nb_unprotected_buf);

	if (Yang_Ok != (err = yang_decode_rtcpCompound(&session->rtcp_compound, &buffer))) {
		return yang_error_wrap(err, "decode rtcp plaintext=%u",	nb_unprotected_buf);
	}

	YangRtcpCommon *rtcp = NULL;
	for (int i = 0; i < session->rtcp_compound.rtcpVector.vsize; i++) {
		rtcp = &session->rtcp_compound.rtcpVector.payload[i];
		err = yang_rtcconn_dispatch_rtcp(session, rtcp);
		if (Yang_Ok != err) {
			yang_rtcpCompound_clear(&session->rtcp_compound);
			return yang_error_wrap(err,
					"cipher=%u, plaintext=%u,  rtcp=(%u,%u,%u,%u)", nb_data,
					nb_unprotected_buf, rtcp->nb_data, rtcp->header.rc,
					rtcp->header.type, rtcp->ssrc);
		}
	}
	yang_rtcpCompound_clear(&session->rtcp_compound);
	return err;

}

yangbool yang_rtcconn_isAlive(YangRtcSession* session){
	if(session==NULL||session->context.state!=Yang_Conn_State_Connected) return yangfalse;
	return session->lastStunTime + session->sessionTimeout > yang_get_system_time();
}


void yang_rtcconn_startudp(YangRtcSession *session) {
	yang_rtcconn_init(session, session->context.streamConfig->streamOptType);
	yang_rtcconn_setSsrc(session, session->context.audioSsrc,session->context.videoSsrc);
}


int32_t yang_rtcconn_send_video_meta(YangRtcSession *session, YangFrame *p) {
#if Yang_Enable_RTC_Video
	if (session->pushH264)
		return session->pushH264->on_spspps(session,session->pushH264->push, p);
	#if	Yang_Enable_H265_Encoding
	if (session->pushH265)
		return session->pushH265->on_spspps(session,session->pushH265->push, p);
	#endif

#endif
	return Yang_Ok;
}

int32_t yang_rtcconn_onVideo(YangRtcSession *session, YangFrame *p) {
#if Yang_Enable_RTC_Video

	if (session==NULL || p==NULL || session->context.state!=Yang_Conn_State_Connected||session->context.dtls->session.state!=YangDtlsStateClientDone)	return Yang_Ok;

	if (p->frametype == YANG_Frametype_Spspps)
		return yang_rtcconn_send_video_meta(session, p);
	if (session->pushH264)
		return session->pushH264->on_video(session, session->pushH264->push, p);
	#if	Yang_Enable_H265_Encoding
	if (session->pushH265)
		return session->pushH265->on_video(session, session->pushH265->push, p);
	#endif

#endif
	return Yang_Ok;

}

int32_t yang_rtcconn_onAudio(YangRtcSession *session, YangFrame *p) {


	if (session==NULL||p==NULL||session->context.state!=Yang_Conn_State_Connected||session->context.dtls->session.state!=YangDtlsStateClientDone)	return Yang_Ok;

#if Yang_Enable_RTC_Audio
	if (session->pushAudio)
		return session->pushAudio->on_audio(session, session->pushAudio->push, p);
#endif

	return Yang_Ok;

}

int32_t yang_rtcconn_onMessage(YangRtcSession *session, YangFrame *p) {

#if Yang_Enable_Datachannel
	if(session==NULL || p==NULL ||session->context.state!=Yang_Conn_State_Connected||
			session->context.dtls->session.isRecvAlert||session->context.dtls->session.state!=YangDtlsStateClientDone)
		return Yang_Ok;

	if(session->datachannel&&session->datachannel->send_message) session->datachannel->send_message(session->datachannel->context,p);
#endif

	return Yang_Ok;
}

void yang_rtcconn_close(YangRtcSession *session) {
	if (session == NULL)	return;

	session->context.dtls->session.isSendAlert = yangtrue;
	if (session->context.dtls&&!session->context.dtls->session.isRecvAlert&&session->context.dtls->sendDtlsAlert){
		session->context.dtls->sendDtlsAlert(&session->context.dtls->session);
	}


	session->context.state = Yang_Conn_State_Closed;
	yang_onConnectionStateChange(session,Yang_Conn_State_Closed);
}


int32_t yang_rtcconn_notify(YangRtcSession *session, YangRtcMessageType mess) {

	return Yang_Ok;
}

void yang_rtcconn_receive(YangRtcSession *session, char *data, int32_t size) {
	if (session==NULL||!session->activeState)	return;

	uint8_t bt=(uint8_t)data[0];
	session->lastStunTime=yang_get_system_time();
	//is rtp rtcp
	if(bt > 127 && bt < 192 && size>12){

		bt=(uint8_t)data[1];
		if (bt>= 192 && bt <= 223) {//rtcp
			yang_rtcconn_on_rtcp(session, data, size);
			return;
		}
		//rtp
		session->startRecv = 1;

		return;
	}
	//is stun
	if(size>0&&(bt==0x00 || bt==0x01)){

			if ( yang_decode_stun2(data, size) != Yang_Ok) {
				yang_error("decode stun packet failed");
				return;
			}


			if (!session->isSendDtls) {
				if (session->context.dtls->startHandShake(&session->context.dtls->session)) yang_error("dtls start handshake failed!");
				session->isSendDtls = yangtrue;
			}

		return;
	}

	//is dtls
		if (bt > 19 && bt < 64) {

			if(session->context.dtls==NULL) return;
#if Yang_Enable_Datachannel
			if (session->context.dtls->processData(session->datachannel,&session->context.dtls->session, data,size) == Yang_Ok && session->context.state == Yang_Conn_State_Connecting) {
#else
			if (session->context.dtls->processData(NULL,&session->context.dtls->session, data,size) == Yang_Ok && session->context.state == Yang_Conn_State_Connecting) {
#endif

				if(session->isServer){
					if( session->context.dtls->session.handshake_done ) {
										session->context.state = Yang_Conn_State_Connected;
										yang_onConnectionStateChange(session,Yang_Conn_State_Connected);
										yang_rtcconn_startTimers(session);
					}
					return;
				}else if (session->context.dtls->session.state == YangDtlsStateClientDone) {
					goto client_sucess;
				}
			}


		}

	client_sucess:
	if(session->context.state == Yang_Conn_State_Connecting) {
		session->context.state = Yang_Conn_State_Connected;
		yang_onConnectionStateChange(session,Yang_Conn_State_Connected);
		yang_rtcconn_startTimers(session);
		if (session->context.streamConfig&&session->context.streamConfig->rtcCallback.sendRequest)
				session->context.streamConfig->rtcCallback.sendRequest(session->context.streamConfig->rtcCallback.context,session->context.streamConfig->uid, 0,Yang_Req_Connected);
	}
	return;
}

void yang_rtcconn_on_ice(YangRtcSession *session,char* remoteIp,int32_t port) {
	if(session==NULL || remoteIp==NULL) return;
	session->context.sock->updateRemoteAddress(&session->context.sock->session,remoteIp,port);
}

int32_t yang_rtcconn_getRemoteSdp(YangRtcSession *session, char *sdpstr){
	if(session==NULL) return ERROR_RTC_SDP;
	int32_t err = Yang_Ok;

	YangSdp sdp;
	yang_memset(&sdp,0,sizeof(YangSdp));
	yang_create_rtcsdp(&sdp);
#if Yang_Enable_RTC_Audio
	if(session->remote_audio==NULL) session->remote_audio=(YangAudioParam*)yang_calloc(sizeof(YangAudioParam),1);
#endif
#if Yang_Enable_RTC_Video
	if(session->remote_video==NULL) session->remote_video=(YangVideoParam*)yang_calloc(sizeof(YangVideoParam),1);
#endif
	if((err=yang_rtcsdp_parse(&sdp,sdpstr))!=Yang_Ok){
		yang_error("sdp parse error!");
	}
	if((err=yang_sdp_parseRemoteSdp(session,&sdp))!=Yang_Ok){
		yang_error("parseRemoteSdp error!");
	}
	yang_destroy_rtcsdp(&sdp);

	return err;
}




void yang_rtcconn_turn_receive(void *psession, char *data, int32_t size){
	if(psession==NULL || data==NULL) return;
	YangRtcSession *session=(YangRtcSession*)psession;
	yang_rtcconn_receive(session,data,size);
}



int32_t yang_rtcconn_createOffer(YangRtcSession *session, char **psdp){
	if(session==NULL) return ERROR_RTC_CONNECT;

	int32_t localport=session->context.streamConfig->localPort;
	YangStreamOptType role=session->context.streamConfig->streamOptType;

	return yang_sdp_genLocalSdp(session,localport, psdp,role);
}




int32_t yang_rtcconn_startRtc(YangRtcSession* session,char* sdp){
	if(session==NULL || sdp==NULL) return ERROR_RTC_PEERCONNECTION;
		int32_t err=Yang_Ok;


		yang_trace("\nstartRtc,port=%d",session->context.streamConfig->localPort);


		session->isServer=session->context.streamConfig->isServer;

		yang_rtcconn_getRemoteSdp(session,sdp);

		yang_stun_createRequestStunPacket(session,session->remoteIcePwd);



		err=yang_create_rtcsocket(session->context.sock,session->context.avinfo->sys.familyType,(YangSocketProtocol)session->context.avinfo->rtc.rtcSocketProtocol,session->context.streamConfig->localPort);
		if(err!=Yang_Ok) return yang_error_wrap(err,"setRemoteDescription error!");

		session->context.sock->updateRemoteAddress(&session->context.sock->session,session->context.streamConfig->remoteIp,session->isServer?0:session->context.streamConfig->remotePort);
		yang_rtcconn_startudp(session);
		session->context.sock->start(&session->context.sock->session);
		return Yang_Ok;
}

yangbool yang_rtcconn_isConnected(YangRtcSession* session){
	if (session == NULL)		return yangfalse;
	return session->context.state == Yang_Conn_State_Connected;
}

int32_t yang_create_rtcConnection(YangRtcConnection* conn,YangStreamConfig* streamconfig,YangAVInfo* avinfo){
	if (conn == NULL ||streamconfig == NULL || avinfo==NULL)		return ERROR_RTC_CONNECT;
    YangRtcSession* session=(YangRtcSession*)yang_calloc(sizeof(YangRtcSession),1);
	conn->session=session;
	yang_create_rtcContext(&session->context);

	yang_memset(&session->rtcp_compound,0,sizeof(YangRtcpCompound));
	yang_create_rtcpCompound(&session->rtcp_compound);

	session->context.streamConfig = streamconfig;
	session->context.sock->session.user = conn;
	session->context.sock->session.receive = g_session_receive;
	session->context.sock->session.startStunTimer = g_yang_startStunTimer;

	session->context.avinfo=avinfo;


	if(streamconfig->remotePort==0)
		streamconfig->remotePort=8000;

	session->isServer=yangfalse;
	session->h264PayloadType=YangH264PayloadType;
	session->h265PayloadType=YangH265PayloadType;
	session->audioPayloadType = YangAudioPayloadType;


	conn->close=yang_rtcconn_close;
	conn->init=yang_rtcconn_init;
	conn->on_video=yang_rtcconn_onVideo;
	conn->on_audio=yang_rtcconn_onAudio;
	conn->on_message=yang_rtcconn_onMessage;
	conn->notify=yang_rtcconn_notify;
	conn->isAlive=yang_rtcconn_isAlive;

	conn->receive=yang_rtcconn_receive;
	conn->updateCandidateAddress=yang_rtcconn_on_ice;
	conn->onConnectionStateChange=yang_onConnectionStateChange;
	conn->setRemoteDescription=yang_rtcconn_startRtc;
	conn->createOffer=yang_rtcconn_createOffer;


	conn->isConnected=yang_rtcconn_isConnected;
	return Yang_Ok;

}

void yang_destroy_rtcConnection(YangRtcConnection *conn) {
	if (conn == NULL)		return;
	YangRtcSession* session=(YangRtcSession*)conn->session;
	session->activeState = yangfalse;


	yang_timer_stop(session->tm_1s);

	yang_destroy_timer(session->tm_1s);

	yang_free(session->tm_1s);


#if Yang_Enable_RTC_Audio
	yang_destroy_pushAudio(session->pushAudio);
	yang_free(session->remote_audio);
#endif

#if Yang_Enable_RTC_Video
	yang_destroy_pushH264(session->pushH264);
	yang_free(session->pushH264);
	#if	Yang_Enable_H265_Encoding
	yang_destroy_pushH265(session->pushH265);
	yang_free(session->pushH265);
	#endif
	yang_free(session->remote_video);
#endif

	yang_destroy_rtcpush(session->push);
	yang_free(session->push);



#if Yang_Enable_Datachannel
	yang_destroy_datachannel(session->datachannel);
	yang_free(session->datachannel);
#endif


	yang_destroy_rtcContext(&session->context);


	yang_destroy_rtcpCompound(&session->rtcp_compound);

#if Yang_Enable_RTC_Audio
	if(session->pushAudioRtpBuffer){
		yang_destroy_rtpBuffer(session->pushAudioRtpBuffer);
		yang_free(session->pushAudioRtpBuffer);
	}
#endif

#if Yang_Enable_RTC_Video
	if(session->pushVideoRtpBuffer){
		yang_destroy_rtpBuffer(session->pushVideoRtpBuffer);
		yang_free(session->pushVideoRtpBuffer);
	}
#endif
	yang_free(conn->session);
}

