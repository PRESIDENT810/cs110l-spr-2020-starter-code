use crate::request;
use crate::response;
use crate::CmdOptions;
use crate::upstream::Upstream;

use std::time::Duration;
use rand::{Rng, SeedableRng};
use tokio::net::{TcpListener, TcpStream};
use tokio::time;

/// Contains information about the state of balancebeam (e.g. what servers we are currently proxying
/// to, what servers have failed, rate limiting counts, etc.)
///
/// You should add fields to this struct in later milestones.
#[derive(Clone)]
pub struct ProxyState {
    /// How frequently we check whether upstream servers are alive (Milestone 4)
    active_health_check_interval: usize,
    /// Where we should send requests when doing active health checks (Milestone 4)
    active_health_check_path: String,
    /// Maximum number of requests an individual IP can make in a minute (Milestone 5)
    #[allow(dead_code)]
    max_requests_per_minute: usize,
    /// Addresses of servers that we are proxying to
    upstream: Upstream,
}

impl ProxyState{
    pub fn new(options: CmdOptions) -> ProxyState{
        return ProxyState{
            upstream: Upstream::new(options.upstream),
            active_health_check_interval: options.active_health_check_interval,
            active_health_check_path: options.active_health_check_path,
            max_requests_per_minute: options.max_requests_per_minute,
        };
    }
}

pub struct Proxy{
    state: ProxyState,
    bind: String,
}

impl Proxy{
    pub fn new(options: CmdOptions) -> Proxy{
        let bind = options.bind.clone();
        let state = ProxyState::new(options);
        return Proxy{state, bind};
    }

    pub async fn start(&self){
        let self_clone = self.clone();
        let interval = self_clone.state.active_health_check_interval.clone();
        let path = self_clone.state.active_health_check_path.clone();
        let upstream_addr_lock = self_clone.state.upstream.upstream_addr_lock.clone();
        let removed_addr_lock = self_clone.state.upstream.removed_addr_lock.clone();

        if interval != 0{
            tokio::spawn(async move {
                let mut interval = time::interval(Duration::from_secs(interval as u64));

                loop {
                    Upstream::active_health_check(
                        upstream_addr_lock.clone(),
                        removed_addr_lock.clone(),
                        path.clone(),
                    ).await;
                    interval.tick().await;
                }
            });
        }

        // Start listening for connections
        let listener = match TcpListener::bind(&self.bind).await {
            Ok(listener) => listener,
            Err(err) => {
                log::error!("[start] Could not bind to {}: {}", &self.bind, err);
                std::process::exit(1);
            }
        };
        log::info!("[start] Listening for requests on {}", &self.bind);

        loop {
            let incoming = listener.accept().await;
            if let Ok((stream, _)) = incoming {
                let state = self.state.clone();
                // Handle the connection!
                tokio::spawn(async move {
                    handle_connection(&state, stream).await;
                });
            };
        }
    }
}

// setup connection with a random upstream server
async fn connect_to_upstream(state: &ProxyState) -> Result<TcpStream, std::io::Error> {
    loop {
        let upstream = &state.upstream;
        let mut rng = rand::rngs::StdRng::from_entropy();
        let upstream_len = upstream.len().await;
        if upstream_len == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "No available upstream servers"));
        }
        let upstream_idx = rng.gen_range(0, upstream_len);
        let upstream_ip = upstream.get(upstream_idx).await;

        let res = TcpStream::connect(&upstream_ip).await;
        match res{
            Ok(stream) => return Ok(stream),
            Err(err) => {
                log::error!("[connect_to_upstream] Failed to connect to upstream {}: {}", upstream_ip, err);
                let upstream_addr_lock = state.upstream.upstream_addr_lock.clone();
                let removed_addr_lock = state.upstream.removed_addr_lock.clone();
                Upstream::try_remove(
                    upstream_addr_lock,
                    removed_addr_lock,
                    &upstream_ip).await;
                continue;
            }
        }
    }
}

// forward the response received from upstream server to client
async fn send_response(client_conn: &mut TcpStream, response: &http::Response<Vec<u8>>) {
    let client_ip = client_conn.peer_addr().unwrap().ip().to_string();
    log::info!("[send_response] {} <- {}", client_ip, response::format_response_line(&response));
    if let Err(error) = response::write_to_stream(&response, client_conn).await {
        log::warn!("[send_response] Failed to send response to client: {}", error);
        return;
    }
}

// handle a connection from client
async fn handle_connection(state: &ProxyState, mut client_conn: TcpStream) {
    let client_ip = client_conn.peer_addr().unwrap().ip().to_string();
    log::info!("Connection received from {}", client_ip);

    // Open a connection to a random destination server
    let mut upstream_conn = match connect_to_upstream(state).await {
        Ok(stream) => stream,
        Err(_error) => {
            let response = response::make_http_error(http::StatusCode::BAD_GATEWAY);
            send_response(&mut client_conn, &response).await;
            return;
        }
    };
    let upstream_ip = client_conn.peer_addr().unwrap().ip().to_string();

    // The client may now send us one or more requests. Keep trying to read requests until the
    // client hangs up or we get an error.
    loop {
        // Read a request from the client
        let mut request = match request::read_from_stream(&mut client_conn).await {
            Ok(request) => request,
            // Handle case where client closed connection and is no longer sending requests
            Err(request::Error::IncompleteRequest(0)) => {
                log::debug!("Client finished sending requests. Shutting down connection");
                return;
            }
            // Handle I/O error in reading from the client
            Err(request::Error::ConnectionError(io_err)) => {
                log::info!("Error reading request from client stream: {}", io_err);
                return;
            }
            Err(error) => {
                log::debug!("Error parsing request: {:?}", error);
                let response = response::make_http_error(match error {
                    request::Error::IncompleteRequest(_)
                    | request::Error::MalformedRequest(_)
                    | request::Error::InvalidContentLength
                    | request::Error::ContentLengthMismatch => http::StatusCode::BAD_REQUEST,
                    request::Error::RequestBodyTooLarge => http::StatusCode::PAYLOAD_TOO_LARGE,
                    request::Error::ConnectionError(_) => http::StatusCode::SERVICE_UNAVAILABLE,
                });
                send_response(&mut client_conn, &response).await;
                continue;
            }
        };
        log::info!(
            "{} -> {}: {}",
            client_ip,
            upstream_ip,
            request::format_request_line(&request)
        );

        // Add X-Forwarded-For header so that the upstream server knows the client's IP address.
        // (We're the ones connecting directly to the upstream server, so without this header, the
        // upstream server will only know our IP, not the client's.)
        request::extend_header_value(&mut request, "x-forwarded-for", &client_ip);

        // Forward the request to the server
        if let Err(error) = request::write_to_stream(&request, &mut upstream_conn).await {
            log::error!("Failed to send request to upstream {}: {}", upstream_ip, error);
            let response = response::make_http_error(http::StatusCode::BAD_GATEWAY);
            send_response(&mut client_conn, &response).await;
            return;
        }
        log::debug!("Forwarded request to server");

        // Read the server's response
        let response = match response::read_from_stream(&mut upstream_conn, request.method()).await {
            Ok(response) => response,
            Err(error) => {
                log::error!("Error reading response from server: {:?}", error);
                let response = response::make_http_error(http::StatusCode::BAD_GATEWAY);
                send_response(&mut client_conn, &response).await;
                return;
            }
        };
        // Forward the response to the client
        send_response(&mut client_conn, &response).await;
        log::debug!("Forwarded response to client");
    }
}