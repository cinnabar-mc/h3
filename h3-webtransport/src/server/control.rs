//! The same CONNECT stream and its cancellation-safe, fused close observation.

use crate::capsule::{Capsules, SessionClose};
use bytes::Buf;
use h3::{error::StreamError, quic, server::RequestStream};
use std::{
    sync::Arc,
    task::{Context, Poll},
};

type Closed = Result<Option<SessionClose>, Arc<StreamError>>;
const DATA_CHUNKS_PER_POLL: usize = 32;

pub(super) struct ConnectControl<S, B> {
    pub(super) stream: RequestStream<S, B>,
    decoder: Capsules,
    receiving_trailers: bool,
    terminal: Option<Closed>,
}

impl<S, B> ConnectControl<S, B> {
    /// Moves the original completed CONNECT response stream without replacing either direction.
    pub(super) fn new(stream: RequestStream<S, B>) -> Self {
        Self {
            stream,
            decoder: Capsules::default(),
            receiving_trailers: false,
            terminal: None,
        }
    }

    /// A previously observed peer terminal never causes a second local close capsule.
    pub(super) fn terminal_observed(&self) -> bool {
        self.terminal.is_some()
    }
}

impl<S: quic::RecvStream, B: Buf> ConnectControl<S, B> {
    /// Retains every partial capsule and actual terminal across dropped borrowed waits.
    pub(super) fn poll_closed(&mut self, cx: &mut Context<'_>) -> Poll<Closed> {
        if let Some(terminal) = &self.terminal {
            return Poll::Ready(terminal.clone());
        }
        for _ in 0..DATA_CHUNKS_PER_POLL {
            let result = if self.receiving_trailers {
                match self.stream.poll_recv_trailers(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => Err(error),
                    Poll::Ready(Ok(_)) => self.decoder.finish().map(|()| None),
                }
            } else {
                match self.stream.poll_recv_data(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => Err(error),
                    Poll::Ready(Ok(None)) => {
                        // The body may end at unvalidated HEADERS before the actual FIN.
                        self.receiving_trailers = true;
                        continue;
                    }
                    Poll::Ready(Ok(Some(mut bytes))) => match self.decoder.receive(&mut bytes) {
                        Ok(None) => continue,
                        result => result,
                    },
                }
            }
            .map_err(Arc::new);
            self.terminal = Some(result.clone());
            return Poll::Ready(result);
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

#[cfg(test)]
mod tests;
