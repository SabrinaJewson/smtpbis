use crate::Command;
use crate::Command::Base;
use std::task::ready;
use crate::Command::*;
use crate::LineCodec;
use crate::LineError;
use crate::Reply;
use crate::command;
use crate::reply::ReplyDefault;
use bytes::Buf;
use bytes::Bytes;
use bytes::BytesMut;
use futures_util::Sink;
use futures_util::future::Either;
use futures_util::future::select;
use futures_util::sink::SinkExt;
use futures_util::stream::Stream;
use futures_util::stream::StreamExt;
use rustyknife::behaviour::Intl;
use rustyknife::behaviour::Legacy;
use rustyknife::rfc5321::Command::*;
use rustyknife::rfc5321::ForwardPath;
use rustyknife::rfc5321::Param;
use rustyknife::rfc5321::ReversePath;
use rustyknife::types::Domain;
use rustyknife::types::DomainPart;
use std::collections::BTreeMap;
use std::fmt::Write;
use std::pin::Pin;
use std::pin::pin;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;
use tokio_util::codec::Framed;
use tokio_util::codec::FramedParts;
use futures_util::stream;
use std::task::Poll;

pub type EhloKeywords = BTreeMap<String, Option<String>>;

pub trait Handler: Send {
    type TlsConfig;

    fn tls_request(&mut self) -> impl Send + Future<Output = Option<Self::TlsConfig>> {
        async { None }
    }

    fn ehlo(
        &mut self,
        domain: DomainPart,
        initial_keywords: EhloKeywords,
    ) -> impl Send + Future<Output = Result<(String, EhloKeywords), Reply>>;
    fn helo(&mut self, domain: Domain) -> impl Send + Future<Output = Option<Reply>>;
    fn rset(&mut self) -> impl Send + Future<Output = ()>;

    fn mail(
        &mut self,
        path: ReversePath,
        params: Vec<Param>,
    ) -> impl Send + Future<Output = Option<Reply>>;
    fn rcpt(
        &mut self,
        path: ForwardPath,
        params: Vec<Param>,
    ) -> impl Send + Future<Output = Option<Reply>>;

    fn data_start(&mut self) -> impl Send + Future<Output = Option<Reply>> {
        async { None }
    }
    fn data<S>(&mut self, stream: S) -> impl Send + Future<Output = Result<Option<Reply>, Error>>
    where
        S: Stream<Item = Result<BytesMut, LineError>> + Send;
    fn bdat<S>(
        &mut self,
        stream: S,
        size: u64,
        last: bool,
    ) -> impl Send + Future<Output = Result<Option<Reply>, Error>>
    where
        S: Stream<Item = Result<BytesMut, LineError>> + Send;

    fn unhandled_command(
        &mut self,
        _command: Command,
    ) -> impl Send + Future<Output = Option<Reply>> {
        async { None }
    }
}

pub struct Config {
    pub enable_smtputf8: bool,
    pub enable_chunking: bool,
    pub enable_starttls: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            enable_smtputf8: true,
            enable_chunking: true,
            enable_starttls: true,
        }
    }
}

pub async fn smtp_server<S, H, Shutdown: Future>(
    socket: S,
    handler: &mut H,
    config: &Config,
    shutdown: Shutdown,
    banner: Option<Bytes>,
) -> Result<LoopExit<H, Shutdown::Output>, Error>
where
    S: AsyncRead + AsyncWrite + Send,
    H: Handler,
{
    let shutdown = pin!(shutdown);
    let mut server = InnerServer {
        handler,
        config,
        state: State::Initial,
        shutdown: Ok(shutdown),
    };

    let mut socket = pin!(socket);
    let res = server.serve(socket.as_mut(), banner).await;
    socket.flush().await?;
    res
}

pub enum LoopExit<H: Handler, T> {
    Done,
    Shutdown(T),
    StartTls(H::TlsConfig),
}

#[derive(Debug, PartialEq)]
enum State {
    Initial,
    Mail,
    Rcpt,
    Bdat,
    Bdatfail,
}

struct InnerServer<'a, H, Shutdown: Future> {
    handler: &'a mut H,
    config: &'a Config,
    state: State,
    shutdown: Result<Pin<&'a mut Shutdown>, Option<Shutdown::Output>>,
}

impl<'a, H: Handler, Shutdown: Future> InnerServer<'a, H, Shutdown> {
    async fn serve<S>(
        &mut self,
        base_socket: Pin<&mut S>,
        banner: Option<Bytes>,
    ) -> Result<LoopExit<H, Shutdown::Output>, Error>
    where
        S: AsyncRead + AsyncWrite + Send,
    {
        let mut socket = Framed::new(base_socket, LineCodec::default());

        if let Some(banner) = banner {
            socket
                .send(Reply::new_checked(220, None, banner).expect("banner should be valid"))
                .await?;
        }

        loop {
            let cmd = match self.read_command(&mut socket).await {
                Ok(cmd) => cmd,
                Err(ReadCommandError::Syntax) => {
                    socket.send(Reply::syntax_error()).await?;
                    continue;
                }
                Err(ReadCommandError::Shutdown(val)) => {
                    socket
                        .send(Reply::new_static(421, None, "Shutting down"))
                        .await?;
                    return Ok(LoopExit::Shutdown(val));
                }
                Err(ReadCommandError::Fatal(e)) => return Err(e),
            };

            match self.dispatch_command(&mut socket, cmd).await? {
                Some(LoopExit::StartTls(tls_config)) => {
                    socket.flush().await?;
                    let FramedParts {
                        mut io, read_buf, ..
                    } = socket.into_parts();
                    // Absolutely do not allow pipelining past a
                    // STARTTLS command.
                    if !read_buf.is_empty() {
                        return Err(Error::Pipelining);
                    }

                    let mut tls_reply = BytesMut::new();
                    Reply::new_static(220, None, "starting TLS").write_to(&mut tls_reply);
                    io.write_all(&tls_reply).await?;

                    return Ok(LoopExit::StartTls(tls_config));
                }
                Some(other) => return Ok(other),
                None => {}
            }
        }
    }

    fn shutdown_check(&mut self) -> Result<(), ReadCommandError<Shutdown::Output>> {
        if matches!(self.state, State::Initial | State::Bdatfail) {
            if let Err(shutdown) = &mut self.shutdown {
                return Err(ReadCommandError::Shutdown(shutdown.take().unwrap()));
            }
        }
        Ok(())
    }

    async fn read_command<S>(
        &mut self,
        reader: &mut S,
    ) -> Result<Command, ReadCommandError<Shutdown::Output>>
    where
        S: Stream<Item = Result<BytesMut, LineError>> + Unpin,
        S: Sink<Reply>,
        ReadCommandError<Shutdown::Output>: From<<S as Sink<Reply>>::Error>,
    {
        self.shutdown_check()?;

        let line = match &mut self.shutdown {
            Ok(shutdown) => match select(reader.next(), shutdown.as_mut()).await {
                Either::Left((cmd, _)) => cmd,
                Either::Right((val, cmd_fut)) => {
                    self.shutdown = Err(Some(val));
                    self.shutdown_check()?;
                    cmd_fut.await
                }
            },
            Err(_) => reader.next().await,
        }
        .ok_or(Error::Eof)??;

        let parse_res = if self.config.enable_smtputf8 {
            command::<Intl>(&line)
        } else {
            command::<Legacy>(&line)
        };

        match parse_res {
            Err(_) => Err(ReadCommandError::Syntax),
            Ok((rem, _)) if !rem.is_empty() => Err(ReadCommandError::Syntax),
            Ok((_, cmd)) => Ok(cmd),
        }
    }

    async fn dispatch_command<S>(
        &mut self,
        socket: &mut Framed<Pin<&mut S>, LineCodec>,
        command: Command,
    ) -> Result<Option<LoopExit<H, Shutdown::Output>>, Error>
    where
        S: AsyncRead + AsyncWrite + Send,
    {
        match command {
            Base(EHLO(domain)) => {
                socket.send(self.do_ehlo(domain).await?).await?;
            }
            Base(HELO(domain)) => {
                socket.send(self.do_helo(domain).await?).await?;
            }
            Base(MAIL(path, params)) => {
                socket.send(self.do_mail(path, params).await?).await?;
            }
            Base(RCPT(path, params)) => {
                socket.send(self.do_rcpt(path, params).await?).await?;
            }
            Base(DATA) => {
                let reply = self.do_data(socket).await?;
                socket.send(reply).await?;
            }
            Base(QUIT) => {
                socket.send(Reply::new_static(221, None, "bye")).await?;
                return Ok(Some(LoopExit::Done));
            }
            Base(RSET) => {
                self.state = State::Initial;
                self.handler.rset().await;
                socket.send(Reply::ok()).await?;
            }
            Ext(crate::Ext::StartTls) if self.config.enable_starttls => {
                if let Some(tls_config) = self.handler.tls_request().await {
                    return Ok(Some(LoopExit::StartTls(tls_config)));
                } else {
                    socket.send(Reply::not_implemented()).await?;
                }
            }
            Ext(crate::Ext::Bdat(size, last)) if self.config.enable_chunking => {
                let reply = self.do_bdat(socket, size, last).await?;
                socket.send(reply).await?;
            }
            _ => {
                let reply = self
                    .handler
                    .unhandled_command(command)
                    .await
                    .unwrap_or_else(Reply::not_implemented);
                socket.send(reply).await?;
            }
        }
        Ok(None)
    }

    async fn do_ehlo(&mut self, domain: DomainPart) -> Result<Reply, Error> {
        let mut initial_keywords = EhloKeywords::new();
        for kw in ["PIPELINING", "ENHANCEDSTATUSCODES"].as_ref() {
            initial_keywords.insert((*kw).into(), None);
        }
        if self.config.enable_smtputf8 {
            initial_keywords.insert("8BITMIME".into(), None);
            initial_keywords.insert("SMTPUTF8".into(), None);
        }
        if self.config.enable_chunking {
            initial_keywords.insert("CHUNKING".into(), None);
        }
        if self.config.enable_starttls {
            initial_keywords.insert("STARTTLS".into(), None);
        }

        match self.handler.ehlo(domain, initial_keywords).await {
            Err(reply) => Ok(reply),
            Ok((greeting, keywords)) => {
                assert!(!greeting.contains('\r') && !greeting.contains('\n'));
                let mut reply_text = format!("{}\n", greeting);

                for (kw, value) in keywords {
                    match value {
                        Some(value) => writeln!(reply_text, "{} {}", kw, value).unwrap(),
                        None => writeln!(reply_text, "{}", kw).unwrap(),
                    }
                }
                self.state = State::Initial;
                Ok(Reply::new_checked(250, None, reply_text).unwrap())
            }
        }
    }

    async fn do_helo(&mut self, domain: Domain) -> Result<Reply, Error> {
        Ok(
            match self.handler.helo(domain).await.with_default(Reply::ok()) {
                Ok(reply) => {
                    self.state = State::Initial;
                    reply
                }
                Err(reply) => reply,
            },
        )
    }

    async fn do_mail(&mut self, path: ReversePath, params: Vec<Param>) -> Result<Reply, Error> {
        Ok(match self.state {
            State::Initial => match self
                .handler
                .mail(path, params)
                .await
                .with_default(Reply::ok())
            {
                Ok(reply) => {
                    self.state = State::Mail;
                    reply
                }
                Err(reply) => reply,
            },
            _ => Reply::bad_sequence(),
        })
    }

    async fn do_rcpt(&mut self, path: ForwardPath, params: Vec<Param>) -> Result<Reply, Error> {
        Ok(match self.state {
            State::Mail | State::Rcpt => match self
                .handler
                .rcpt(path, params)
                .await
                .with_default(Reply::ok())
            {
                Ok(reply) => {
                    self.state = State::Rcpt;
                    reply
                }
                Err(reply) => reply,
            },
            _ => Reply::bad_sequence(),
        })
    }

    async fn do_data<S>(&mut self, socket: &mut S) -> Result<Reply, Error>
    where
        S: Stream<Item = Result<BytesMut, LineError>> + Unpin + Send,
        S: Sink<Reply>,
        Error: From<<S as Sink<Reply>>::Error>,
    {
        Ok(match self.state {
            State::Rcpt => match self
                .handler
                .data_start()
                .await
                .with_default(Reply::data_ok())
            {
                Ok(reply) => {
                    socket.send(reply).await?;

                    let mut body_stream = read_body_data(socket).fuse();
                    let mut reply = self
                        .handler
                        .data(&mut body_stream)
                        .await?
                        .unwrap_or_else(Reply::ok);

                    if !body_stream.is_done() {
                        drop(body_stream);
                        // The handler MUST signal an error.
                        if !reply.is_error() {
                            reply = Reply::data_abort();
                        }

                        socket.send(reply).await?;

                        return Err(Error::DataAbort);
                    }

                    self.state = State::Initial;
                    reply
                }
                Err(reply) => reply,
            },
            State::Initial => Reply::no_mail_transaction(),
            State::Mail => Reply::no_valid_recipients(),
            State::Bdat | State::Bdatfail => {
                Reply::new_static(503, None, "BDAT may not be mixed with DATA")
            }
        })
    }

    async fn do_bdat<S>(
        &mut self,
        socket: &mut Framed<S, LineCodec>,
        chunk_size: u64,
        last: bool,
    ) -> Result<Reply, Error>
    where
        Framed<S, LineCodec>: Stream<Item = Result<BytesMut, LineError>>
            + Sink<Reply, Error = LineError>
            + Send
            + Unpin,
    {
        Ok(match self.state {
            State::Rcpt | State::Bdat => {
                let mut body_stream = read_body_bdat(socket, chunk_size).fuse();

                let reply = self
                    .handler
                    .bdat(&mut body_stream, chunk_size, last)
                    .await?;

                if !body_stream.is_done() {
                    let mut reply = reply.unwrap_or_else(Reply::ok);

                    drop(body_stream);
                    // The handler MUST signal an error.
                    if !reply.is_error() {
                        reply = Reply::data_abort();
                    }

                    socket.send(reply).await?;

                    return Err(Error::DataAbort);
                }

                match reply.with_default(Reply::ok()) {
                    Ok(reply) => {
                        if last {
                            self.state = State::Initial
                        } else {
                            self.state = State::Bdat
                        }
                        reply
                    }
                    Err(reply) => {
                        self.state = State::Bdatfail;
                        reply
                    }
                }
            }
            State::Mail => Reply::no_valid_recipients(),
            _ => Reply::no_mail_transaction(),
        })
    }
}

#[derive(Debug)]
pub enum Error {
    Eof,
    Framing(LineError),
    Io(std::io::Error),
    Pipelining,
    DataAbort,
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<LineError> for Error {
    fn from(source: LineError) -> Self {
        match source {
            LineError::Io(e) => Self::Io(e),
            _ => Self::Framing(source),
        }
    }
}

#[derive(Debug)]
enum ReadCommandError<T> {
    Fatal(Error),
    Syntax,
    Shutdown(T),
}

impl<T> From<Error> for ReadCommandError<T> {
    fn from(e: Error) -> Self {
        Self::Fatal(e)
    }
}

impl<T> From<LineError> for ReadCommandError<T> {
    fn from(e: LineError) -> Self {
        Self::Fatal(Error::Framing(e))
    }
}

fn read_body_data<S>(source: &mut S) -> impl Stream<Item = Result<BytesMut, LineError>> + '_
where
    S: Stream<Item = Result<BytesMut, LineError>> + Unpin,
{
    let mut done = false;
    stream::poll_fn(move |cx| {
        if done {
            return Poll::Ready(None);
        }
        Poll::Ready(match ready!(source.poll_next_unpin(cx)) {
            None => {
                done = true;
                Some(Err(LineError::DataAbort))
            }
            Some(Ok(line)) if line.as_ref() == b".\r\n" => None,
            Some(Ok(mut line)) => {
                if line.starts_with(b".") {
                    line.advance(1);
                }
                Some(Ok(line))
            },
            Some(Err(e)) => Some(Err(e)),
        })
    })
}

fn read_body_bdat<S>(
    socket: &mut Framed<S, LineCodec>,
    size: u64,
) -> impl Stream<Item = Result<BytesMut, LineError>> + '_
where
    Framed<S, LineCodec>: Stream<Item = Result<BytesMut, LineError>> + Unpin,
{
    socket.codec_mut().chunking_mode(size);

    let mut done = false;
    stream::poll_fn(move |cx| {
        if done {
            return Poll::Ready(None);
        }
        Poll::Ready(match ready!(socket.poll_next_unpin(cx)) {
            None => {
                done = true;
                Some(Err(LineError::DataAbort))
            }
            Some(Err(LineError::ChunkingDone)) => None,
            Some(res) => Some(res),
        })
    })
}
