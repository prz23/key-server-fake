#![allow(dead_code)]
#![allow(unused_must_use)]

use std::collections::HashMap;
// #[cfg(all(feature = "normal"))]
// use std::fs;
#[cfg(all(feature = "mesalock_sgx", not(target_env = "sgx")))]
use std::fs;
use std::io::{self, BufReader, Read, Write};
use std::net;
use std::net::Shutdown;
#[cfg(all(feature = "mesalock_sgx", not(target_env = "sgx")))]
use std::prelude::v1::*;
use std::sync::Arc;
use std::vec;
use std::vec::Vec;

use http::{response::Builder, Method, Request, Response, Version};
use log::*;
use mio::net::{TcpListener, TcpStream};
use rustls::{NoClientAuth, Session};
use serde::*;

#[cfg(all(feature = "mesalock_sgx", not(target_env = "sgx")))]
use uera;

use crate::key_mount::{handle_msgs, handle_sync_mission};
use primitives::key_types::KeyServerParams;
use round_based::Msg;

// use webpki;
// Token for our listening socket.
const LISTENER: mio::Token = mio::Token(0);
const NOT_FOUND: &[u8] = b"";

pub trait Cors {
    fn cors(self) -> Builder;
}

impl Cors for Builder {
    fn cors(self) -> Builder {
        self.header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Methods", "POST, GET, OPTION, DELETE")
    }
}

// Which mode the server operates in.
#[derive(Clone)]
enum ServerMode {
    /// Write back received bytes
    Echo,

    /// Do one read, then write a bodged HTTP response and
    /// cleanly close the connection.
    Http,

    /// Forward traffic to/from given port on localhost.
    Forward(u16),
}

/// This binds together a TCP listening socket, some outstanding
/// connections, and a TLS server configuration.
struct TlsServer {
    server: TcpListener,
    connections: HashMap<mio::Token, Connection>,
    next_id: usize,
    tls_config: Arc<rustls::ServerConfig>,
    mode: ServerMode,
    ra: bool,
}

impl TlsServer {
    fn new(server: TcpListener, mode: ServerMode, cfg: Arc<rustls::ServerConfig>, ra: bool) -> TlsServer {
        TlsServer {
            server,
            connections: HashMap::new(),
            next_id: 2,
            tls_config: cfg,
            mode,
            ra,
        }
    }

    fn accept(&mut self, poll: &mut mio::Poll) -> bool {
        match self.server.accept() {
            Ok((socket, addr)) => {
                debug!("Accepting new connection from {:?}", addr);

                let tls_session = rustls::ServerSession::new(&self.tls_config);

                let mode = self.mode.clone();

                let token = mio::Token(self.next_id);
                self.next_id += 1;

                socket.set_keepalive(Some(std::time::Duration::from_secs(30)));
                let connection = Connection::new(socket, token, mode, tls_session);

                self.connections.insert(token, connection);
                self.connections[&token].register(poll);
                true
            }
            Err(e) => {
                error!("encountered error while accepting connection; err={:?}", e);
                false
            }
        }
    }

    fn conn_event(&mut self, poll: &mut mio::Poll, event: &mio::event::Event) {
        let token = event.token();

        if self.connections.contains_key(&token) {
            self.connections.get_mut(&token).unwrap().ready(poll, event);

            if self.connections[&token].is_closed() {
                self.connections.remove(&token);
            }
        }
    }
}

/// Temporary preservation of a Header from a segmented delivery Request
struct Conti100 {
    pub req: http::request::Parts,
    pub content_len: usize,
    pub is_body_get: bool,
    pub buf: Vec<u8>,
}

impl Conti100 {
    /// Reset & initialize the temporary storage
    fn new() -> Conti100 {
        let (part, _) = Request::new(vec![0u8]).into_parts();
        Conti100 {
            req: part,
            content_len: 0usize,
            is_body_get: false,
            buf: Vec::new(),
        }
    }
    /// Set new temporary Header
    fn set(req: http::request::Parts, len: usize, part: &mut Vec<u8>) -> Conti100 {
        let mut buf = Vec::new();
        buf.append(part);
        Conti100 {
            req,
            content_len: len,
            is_body_get: true,
            buf,
        }
    }

    fn append(&mut self, data: &mut Vec<u8>) {
        self.buf.append(data)
    }

    fn is_finish(&self) -> bool {
        self.buf.len() >= self.content_len
    }
}

/// This is a connection which has been accepted by the server,
/// and is currently being served.
///
/// It has a TCP-level stream, a TLS-level session, and some
/// other state/metadata.
struct Connection {
    socket: TcpStream,
    token: mio::Token,
    closing: bool,
    closed: bool,
    mode: ServerMode,
    tls_session: rustls::ServerSession,
    back: Option<TcpStream>,
    sent_http_response: bool,
    tmp_req: Conti100,
}

/// Open a plaintext TCP-level connection for forwarded connections.
fn open_back(mode: &ServerMode) -> Option<TcpStream> {
    match *mode {
        ServerMode::Forward(ref port) => {
            let addr = net::SocketAddrV4::new(net::Ipv4Addr::new(127, 0, 0, 1), *port);
            let conn = TcpStream::connect(&net::SocketAddr::V4(addr)).unwrap();
            Some(conn)
        }
        _ => None,
    }
}

/// This used to be conveniently exposed by mio: map EWOULDBLOCK
/// errors to something less-errory.
fn try_read(r: io::Result<usize>) -> io::Result<Option<usize>> {
    match r {
        Ok(len) => Ok(Some(len)),
        Err(e) => {
            if e.kind() == io::ErrorKind::WouldBlock {
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}

impl Connection {
    fn new(socket: TcpStream, token: mio::Token, mode: ServerMode, tls_session: rustls::ServerSession) -> Connection {
        let back = open_back(&mode);
        Connection {
            socket,
            token,
            closing: false,
            closed: false,
            mode,
            tls_session,
            back,
            sent_http_response: false,
            tmp_req: Conti100::new(),
        }
    }

    /// We're a connection, and we have something to do.
    fn ready(&mut self, poll: &mut mio::Poll, ev: &mio::event::Event) {
        // If we're readable: read some TLS.  Then
        // see if that yielded new plaintext.  Then
        // see if the backend is readable too.
        if ev.readiness().is_readable() {
            self.do_tls_read();
            self.try_plain_read();
            self.try_back_read();
        }

        if ev.readiness().is_writable() {
            self.do_tls_write();
        }

        if self.closing {
            let _ = self.socket.shutdown(Shutdown::Both);
            self.close_back();
            self.closed = true;
        } else {
            self.reregister(poll);
        }
    }

    /// Close the backend connection for forwarded sessions.
    fn close_back(&mut self) {
        if self.back.is_some() {
            let back = self.back.as_mut().unwrap();
            back.shutdown(Shutdown::Both).unwrap();
        }
        self.back = None;
    }

    fn do_tls_read(&mut self) {
        // Read some TLS data.
        let rc = self.tls_session.read_tls(&mut self.socket);
        if rc.is_err() {
            let err = rc.unwrap_err();

            if let io::ErrorKind::WouldBlock = err.kind() {
                return;
            }
            match err.raw_os_error() {
                Some(104i32) => (),
                Some(54i32) => (),
                _ => error!("read error {:?}", err),
            }
            self.closing = true;
            return;
        }

        if rc.unwrap() == 0 {
            debug!("eof");
            self.closing = true;
            return;
        }

        // Process newly-received TLS messages.
        let processed = self.tls_session.process_new_packets();
        if processed.is_err() {
            error!("cannot process packet: {:?}", processed);
            self.closing = true;
            return;
        }
    }

    fn try_plain_read(&mut self) {
        // Read and process all available plaintext.
        let mut buf = Vec::new();

        let rc = self.tls_session.read_to_end(&mut buf);
        if rc.is_err() {
            //error!("plaintext read failed: {:?}", rc);
            self.closing = true;
            return;
        }

        if !buf.is_empty() {
            debug!("plaintext read {:?}", buf.len());
            self.incoming_plaintext(&buf);
        }
    }

    fn try_back_read(&mut self) {
        if self.back.is_none() {
            return;
        }

        // Try a non-blocking read.
        let mut buf = [0u8; 1024];
        let back = self.back.as_mut().unwrap();
        let rc = try_read(back.read(&mut buf));

        if rc.is_err() {
            error!("backend read failed: {:?}", rc);
            self.closing = true;
            return;
        }

        let maybe_len = rc.unwrap();

        // If we have a successful but empty read, that's an EOF.
        // Otherwise, we shove the data into the TLS session.
        match maybe_len {
            Some(len) if len == 0 => {
                debug!("back eof");
                self.closing = true;
            }
            Some(len) => {
                self.tls_session.write_all(&buf[..len]).unwrap();
            }
            None => {}
        };
    }

    /// Process some amount of received plaintext.
    fn incoming_plaintext(&mut self, buf: &[u8]) {
        match self.mode {
            ServerMode::Echo => {
                self.tls_session.write_all(buf).unwrap();
            }
            ServerMode::Http => {
                self.send_http_response_once(buf);
            }
            ServerMode::Forward(_) => {
                self.back.as_mut().unwrap().write_all(buf).unwrap();
            }
        }
    }

    fn send_http_response_once(&mut self, buf: &[u8]) {
        trace!("=====buf is [{:?}]=====", buf.len());
        let request_g;

        if self.tmp_req.is_body_get == false {
            let mut stream = rustls::Stream::new(&mut self.tls_session, &mut self.socket);

            let parse_result = parse(&buf.to_vec());
            if parse_result.is_err() {
                error!("parse error");
                let _ = match stream.write(&Response::builder().cors().status(404).body(vec![]).unwrap().flat()) {
                    Ok(_) => (),
                    Err(_) => {
                        self.closing = true;
                        return;
                    }
                };
                self.sent_http_response = true;
                self.tls_session.send_close_notify();
                return;
            }
            let (request, expects, content_len) = parse_result.unwrap();

            if expects || buf.len() < content_len {
                debug!("EXPECT BODY");
                let _ = match stream.write(&Response::builder().cors().status(100).body(vec![]).unwrap().flat()) {
                    Ok(_) => (),
                    Err(_) => {
                        self.closing = true;
                        return;
                    }
                };
                debug!("EXPECT BODY response");
                let mut body = request.body().to_vec().clone();
                let (parts, _) = request.into_parts();
                self.tmp_req = Conti100::set(parts, content_len, &mut body);
                return;
            }
            request_g = request;
        } else {
            debug!("EXPECT BODY get, body len: {}", self.tmp_req.buf.len());
            self.tmp_req.append(&mut buf.to_vec().clone());
            if !self.tmp_req.is_finish() {
                // continue to read data from client
                return;
            } else {
                request_g = Request::builder()
                    .method(self.tmp_req.req.method.clone())
                    .uri(self.tmp_req.req.uri.clone())
                    .body(self.tmp_req.buf.clone())
                    .unwrap(); //request_g = Request::from_parts(self.tmp_req.req, body);

                self.tmp_req = Conti100::new();
                debug!("EXPECT BODY get finished");
            }
        }

        let data = self.process(request_g).flat();

        let mut stream = rustls::Stream::new(&mut self.tls_session, &mut self.socket);
        let res = match stream.write(&data) {
            Ok(_) => (),
            Err(e) => {
                error!("write error:{:?}", e);
                self.closing = true;
                return;
            }
        };
        trace!("=====send response[{:?}]=====", res); //self.tls_session.write_all(&data).unwrap();
        self.sent_http_response = true;
        self.tls_session.send_close_notify();
    }

    fn do_tls_write(&mut self) {
        let rc = self.tls_session.write_tls(&mut self.socket);
        if rc.is_err() {
            error!("write failed {:?}", rc);
            self.closing = true;
            return;
        }
    }

    fn register(&self, poll: &mut mio::Poll) {
        poll.register(
            &self.socket,
            self.token,
            self.event_set(),
            mio::PollOpt::level() | mio::PollOpt::oneshot(),
        )
            .unwrap();

        if self.back.is_some() {
            poll.register(
                self.back.as_ref().unwrap(),
                self.token,
                mio::Ready::readable(),
                mio::PollOpt::level() | mio::PollOpt::oneshot(),
            )
                .unwrap();
        }
    }

    fn reregister(&self, poll: &mut mio::Poll) {
        poll.reregister(
            &self.socket,
            self.token,
            self.event_set(),
            mio::PollOpt::level() | mio::PollOpt::oneshot(),
        )
            .unwrap();

        if self.back.is_some() {
            poll.reregister(
                self.back.as_ref().unwrap(),
                self.token,
                mio::Ready::readable(),
                mio::PollOpt::level() | mio::PollOpt::oneshot(),
            )
                .unwrap();
        }
    }

    /// What IO events we're currently waiting for,
    /// based on wants_read/wants_write.
    fn event_set(&self) -> mio::Ready {
        let rd = self.tls_session.wants_read();
        let wr = self.tls_session.wants_write();

        if rd && wr {
            mio::Ready::readable() | mio::Ready::writable()
        } else if wr {
            mio::Ready::writable()
        } else {
            mio::Ready::readable()
        }
    }

    fn is_closed(&self) -> bool {
        self.closed
    }

    fn process(&self, req: Request<Vec<u8>>) -> Response<Vec<u8>> {
        debug!("Request Method {}, uri {}", req.method(), req.uri());
        match *req.method() {
            Method::POST => {
                let output = match req.uri().path() {
                    "/command" => {
                        // response
                        let data: KeyServerParams = match serde_json::from_slice(req.body()) {
                            Ok(p) => p,
                            Err(e) => {
                                return Response::builder()
                                    .cors()
                                    .status(500)
                                    .body(e.to_string().into_bytes())
                                    .unwrap();
                            }
                        };
                        let process_res = handle_sync_mission(data);
                        // Allows error messages to be returned if 404 is not caught by the front end
                        match serde_json::to_string(&process_res) {
                            Ok(o) => o,
                            Err(e) => {
                                error!("serde output error: {}", e.to_string());
                                return Response::builder().cors().status(500).body(NOT_FOUND.to_vec()).unwrap();
                            }
                        }
                    }
                    "/round_msg" => {
                        let (key, msgs): (String, Vec<Msg<String>>) = match serde_json::from_slice(req.body()) {
                            Ok(p) => p,
                            Err(e) => {
                                return Response::builder()
                                    .cors()
                                    .status(500)
                                    .body(e.to_string().into_bytes())
                                    .unwrap();
                            }
                        };
                        let res = handle_msgs(key, msgs);
                        match serde_json::to_string(&res) {
                            Ok(o) => o,
                            Err(e) => {
                                error!("serde output error: {}", e.to_string());
                                return Response::builder().cors().status(500).body(NOT_FOUND.to_vec()).unwrap();
                            }
                        }
                    }
                    _ => {
                        return Response::builder().cors().status(400).body(NOT_FOUND.to_vec()).unwrap();
                    }
                };
                debug!("output = {:?}", output);
                let res_bytes = output.into_bytes();
                let response = Response::builder()
                    .cors()
                    .status(200)
                    .version(Version::HTTP_11)
                    .header("connection", "close")
                    .header("content-type", "application/json")
                    .header("content-length", res_bytes.len())
                    .body(res_bytes)
                    .unwrap();
                debug!("response :{:?}", response);
                return response;
            }
            _ => {
                error!("No matching routes for {} {}", req.method(), req.uri());
                return Response::builder().cors().status(404).body(NOT_FOUND.to_vec()).unwrap();
            }
        };
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Args {
    cmd_echo: bool,
    cmd_http: bool,
    cmd_forward: bool,
    flag_port: Option<u16>, //Listen on PORT [default: 443].
    flag_verbose: bool,
    flag_protover: Vec<String>,
    flag_suite: Vec<String>,
    flag_proto: Vec<String>,
    flag_certs: Option<String>,
    flag_key: Option<String>,
    flag_ocsp: Option<String>,
    flag_auth: Option<String>,
    flag_require_auth: bool,
    flag_resumption: bool,
    flag_tickets: bool,
    arg_fport: Option<u16>,
    flag_remote_attestation: bool,
}

impl Args {
    pub fn set_port(&mut self, p: u16) {
        self.flag_port = Some(p);
    }
    pub fn set_cert_keys(&mut self, cert: String, key: String) {
        self.flag_certs = Some(cert);
        self.flag_key = Some(key);
    }
    pub fn set_ra(&mut self, p: bool) {
        self.flag_remote_attestation = p;
    }
}

impl Default for Args {
    fn default() -> Self {
        Self {
            cmd_echo: false,
            cmd_http: true,
            cmd_forward: false,
            flag_port: Some(8000), //Listen on PORT [default: 443].
            flag_verbose: false,
            flag_protover: Vec::new(),
            flag_suite: Vec::new(),
            flag_proto: Vec::new(),
            flag_certs: None,
            flag_key: None,
            flag_ocsp: None,
            flag_auth: None,
            flag_require_auth: false,
            flag_resumption: false,
            flag_tickets: false,
            arg_fport: None,
            flag_remote_attestation: false,
        }
    }
}

fn load_certs(_filename: &str) -> Vec<rustls::Certificate> {
    let root_ca_bin = include_bytes!("../../test-ca/end.fullchain");
    let mut reader = BufReader::new(&root_ca_bin[..]);
    rustls::internal::pemfile::certs(&mut reader).unwrap()
}

fn load_private_key(_filename: &str) -> rustls::PrivateKey {
    let rsa_keys = {
        let root_ca_bin = include_bytes!("../../test-ca/end.key");
        let mut reader = BufReader::new(&root_ca_bin[..]);
        rustls::internal::pemfile::rsa_private_keys(&mut reader).expect("file contains invalid rsa private key")
    };

    let pkcs8_keys = {
        let root_ca_bin = include_bytes!("../../test-ca/end.key");
        let mut reader = BufReader::new(&root_ca_bin[..]);
        rustls::internal::pemfile::pkcs8_private_keys(&mut reader)
            .expect("file contains invalid pkcs8 private key (encrypted keys not supported)")
    };

    // prefer to load pkcs8 keys
    if !pkcs8_keys.is_empty() {
        pkcs8_keys[0].clone()
    } else {
        assert!(!rsa_keys.is_empty());
        rsa_keys[0].clone()
    }
}

fn make_config(_enable_ra: bool, cert: &str, key: &str) -> Arc<rustls::ServerConfig> {
    let mut config = rustls::ServerConfig::new(NoClientAuth::new());

    #[cfg(all(feature = "normal"))]
        let certs = load_certs(cert);
    #[cfg(all(feature = "normal"))]
        let privkey = load_private_key(key);

    #[cfg(all(feature = "mesalock_sgx", not(target_env = "sgx")))]
        let linkable = true;
    #[cfg(all(feature = "mesalock_sgx", not(target_env = "sgx")))]
        let (certs, privkey) = uera::creat_cert_and_prikey(linkable).unwrap();

    config
        .set_single_cert_with_ocsp_and_sct(certs, privkey, vec![], vec![])
        .unwrap();
    Arc::new(config)
}

pub fn parse(plaintext: &Vec<u8>) -> Result<(Request<Vec<u8>>, bool, usize), ()> {
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut parse_req = httparse::Request::new(&mut headers);

    match parse_req.parse(&plaintext) {
        Ok(httparse::Status::Complete(parsed_len)) => {
            debug!("Request.parse Complete({})", parsed_len);
            // content-type | content-length
            let mut content_length = None;
            let header = parse_req
                .headers
                .iter()
                .find(|h| h.name.to_lowercase() == "content-length");
            if let Some(&h) = header {
                content_length = usize::from_str_radix(std::str::from_utf8(h.value).unwrap(), 10).ok();
            }

            // true if the client sent a `Expect: 100-continue` header
            let expects_continue: bool = match parse_req.headers.iter().find(|h| h.name.to_lowercase() == "expect") {
                Some(header) => std::str::from_utf8(header.value).unwrap().to_lowercase() == "100-continue",
                None => false,
            };

            // copy to http:Request
            let mut rb = Request::builder()
                .method(parse_req.method.unwrap())
                .version(Version::HTTP_11)
                .uri(parse_req.path.unwrap());

            for header in parse_req.headers {
                rb = rb.header(header.name.clone(), header.value.clone());
            }

            // find pos of body
            let (_headers, body) = plaintext.split_at(parsed_len);
            if let Some(len) = content_length {
                let body_len = body.len();
                debug!(
                    "plaintext {:?} parsed_len {:?} ---  body_len {:?} content_length {:?} -- expects_continue {:?}",
                    plaintext.len(),
                    parsed_len,
                    body_len,
                    len,
                    expects_continue
                );
            }

            let response = rb.body(body.to_vec()).unwrap();
            return Ok((response, expects_continue, content_length.unwrap_or_default()));
        }
        Ok(httparse::Status::Partial) => {
            warn!("httparse Status in Partial");
            return Err(());
        }
        Err(e) => {
            error!("e : {}", e.to_string());
            return Err(());
        }
    };
}

pub fn start_server(args: Args, max_conn: u16) {
    debug!("====start tls key server====");
    debug!(target: "tlsserver", "====start tls key server====");
    let mut addr: net::SocketAddr = "0.0.0.0:443".parse().unwrap();
    addr.set_port(args.flag_port.unwrap_or(443));

    let mode = ServerMode::Http;

    let config = make_config(
        args.flag_remote_attestation,
        &args.flag_certs.unwrap(),
        &args.flag_key.unwrap(),
    );

    let listener = TcpListener::bind(&addr).expect("cannot listen on port");
    let mut poll = mio::Poll::new().unwrap();
    poll.register(&listener, LISTENER, mio::Ready::readable(), mio::PollOpt::level())
        .unwrap();

    let mut tlsserv = TlsServer::new(listener, mode, config, args.flag_remote_attestation);

    let max_conn = max_conn as u8;
    let mut events = mio::Events::with_capacity(256);
    'outer: loop {
        poll.poll(&mut events, None).unwrap();

        for event in events.iter() {
            match event.token() {
                LISTENER => {
                    if tlsserv.connections.len() as u8 == max_conn {
                        continue;
                    }
                    if !tlsserv.accept(&mut poll) {
                        break 'outer;
                    }
                }
                _ => tlsserv.conn_event(&mut poll, &event),
            }
        }
    }
}

fn header_flat<T>(res: &Response<T>) -> Vec<u8> {
    let mut data: Vec<u8> = Vec::new();
    let status = res.status();
    let s = format!(
        "HTTP/1.1 {} {}\r\n",
        status.as_str(),
        status.canonical_reason().unwrap_or("Unsupported Status")
    );
    data.extend_from_slice(&s.as_bytes());
    for (key, value) in res.headers().iter() {
        data.extend_from_slice(key.as_str().as_bytes());
        data.extend_from_slice(b": ");
        data.extend_from_slice(value.as_bytes());
        data.extend_from_slice(b"\r\n");
    }

    data.extend_from_slice(b"\r\n");
    data
}

pub trait Flat {
    fn flat(&self) -> Vec<u8>;
}

impl<T> Flat for Response<T>
    where
        T: AsRef<[u8]>,
{
    fn flat(&self) -> Vec<u8> {
        let mut data = header_flat(&self);
        data.extend_from_slice(self.body().as_ref());
        return data;
    }
}

fn error_response(body: String) -> Vec<u8> {
    Response::builder().cors().status(404).body(body).unwrap().flat()
}

fn main() {

}