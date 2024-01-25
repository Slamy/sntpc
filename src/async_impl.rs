use crate::types::{
    Error, NtpContext, NtpPacket, NtpResult, NtpTimestampGenerator,
    RawNtpPacket, Result, SendRequestResult,
};
use crate::{get_ntp_timestamp, process_response};
use embassy_net::udp::UdpSocket;
use embassy_net::IpEndpoint;
#[cfg(feature = "log")]
use log::debug;

#[cfg(feature = "std")]
use std::net::SocketAddr;
#[cfg(feature = "tokio")]
use tokio::net::{lookup_host, ToSocketAddrs};

pub async fn sntp_send_request<'a>(
    addr: IpEndpoint,
    socket: &UdpSocket<'a>,
    context: NtpContext<impl NtpTimestampGenerator>,
) -> Result<SendRequestResult>
{
    #[cfg(feature = "log")]
    debug!("Address: {:?}, Socket: {:?}", addr, socket);
    let request = NtpPacket::new(context.timestamp_gen);

    let buf = RawNtpPacket::from(&request);

    socket.send_to(&buf.0, addr).await.map_err(|_| Error::Network)?;

    Ok(SendRequestResult::from(request))
}

pub async fn sntp_process_response<'a>(
    addr: IpEndpoint,
    socket: &UdpSocket<'a>,
    mut context: NtpContext<impl NtpTimestampGenerator>,
    send_req_result: SendRequestResult,
) -> Result<NtpResult>
{
    let mut response_buf = RawNtpPacket::default();
    let (response, src) = socket.recv_from(response_buf.0.as_mut()).await.map_err(|_| Error::Network)?;
    context.timestamp_gen.init();
    let recv_timestamp = get_ntp_timestamp(context.timestamp_gen);
    #[cfg(feature = "log")]
    debug!("Response: {}", response);

    if addr != src {
        return Err(Error::ResponseAddressMismatch);
    }

    if response != core::mem::size_of::<NtpPacket>() {
        return Err(Error::IncorrectPayload);
    }

    let result =
        process_response(send_req_result, response_buf, recv_timestamp);

    if let Ok(_r) = &result {
        #[cfg(feature = "log")]
        debug!("{:?}", _r);
    }

    result
}

pub async fn get_time<'a>(
    addr: IpEndpoint,
    socket: &embassy_net::udp::UdpSocket<'a>,
    context: NtpContext<impl NtpTimestampGenerator + Copy>,
) -> Result<NtpResult>
{
    let result = sntp_send_request(addr, socket, context).await?;

    sntp_process_response(addr, socket, context, result).await
}
