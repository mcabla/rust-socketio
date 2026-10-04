use adler32::adler32;
use async_stream::try_stream;
use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use bytes::{BufMut, Bytes, BytesMut};
use futures_util::{Stream, StreamExt};
use http::HeaderMap;
use native_tls::TlsConnector;
use reqwest::{Client, ClientBuilder, Response};
use std::collections::VecDeque;
use std::fmt::Debug;
use std::time::{Duration, SystemTime};
use std::{pin::Pin, sync::Arc};
use tokio::sync::{oneshot, RwLock};
use url::Url;

use crate::asynchronous::generator::StreamGenerator;
use crate::{asynchronous::transport::AsyncTransport, error::Result, Error};

/// Longest a long-poll GET may stay open; the server answers well within its
/// ping interval, so a longer wait means the connection is dead.
const POLL_TIMEOUT: Duration = Duration::from_secs(75);
/// Longest a small POST may take. Sends are serialized (including the pong),
/// so one hung POST would otherwise block the connection forever.
const POST_TIMEOUT: Duration = Duration::from_secs(20);
/// Extra time per byte for large POSTs on a slow uplink (25 kB/s worst case).
const POST_BYTES_PER_EXTRA_SECOND: usize = 25_000;
/// Smaller batches keep each POST short, so a pong queued behind one waits
/// little; well below the server's default maxHttpBufferSize (1e6 bytes).
const MAX_BATCH_BYTES: usize = 256_000;
/// Engine.IO v4 separates the packets of one HTTP payload with this byte.
const PAYLOAD_SEPARATOR: u8 = 0x1e;

type SendResult = std::result::Result<(), String>;

/// Packets waiting for the single writer, as the JS client's writeBuffer: while
/// one POST is in flight new packets (such as the pong) queue up, and the next
/// POST carries all of them. One packet per round trip, as before, let a pong
/// wait behind every queued message.
#[derive(Default)]
struct WriteQueue {
    pending: VecDeque<(Bytes, oneshot::Sender<SendResult>)>,
    writing: bool,
}

/// Without timeouts a request on a silently dropped connection never finishes,
/// and idle pooled connections may be reused after the server closed them.
fn configured(builder: ClientBuilder) -> ClientBuilder {
    builder
        .connect_timeout(Duration::from_secs(10))
        .pool_idle_timeout(Duration::from_secs(2))
        .tcp_keepalive(Duration::from_secs(15))
}

/// An asynchronous polling type. Makes use of the nonblocking reqwest types and
/// methods.
#[derive(Clone)]
pub struct PollingTransport {
    client: Client,
    base_url: Arc<RwLock<Url>>,
    generator: StreamGenerator<Bytes>,
    queue: Arc<std::sync::Mutex<WriteQueue>>,
}

impl PollingTransport {
    pub fn new(
        base_url: Url,
        tls_config: Option<TlsConnector>,
        opening_headers: Option<HeaderMap>,
    ) -> Self {
        let client = match (tls_config, opening_headers) {
            (Some(config), Some(map)) => configured(ClientBuilder::new())
                .use_preconfigured_tls(config)
                .default_headers(map)
                .build()
                .unwrap(),
            (Some(config), None) => configured(ClientBuilder::new())
                .use_preconfigured_tls(config)
                .build()
                .unwrap(),
            (None, Some(map)) => configured(ClientBuilder::new())
                .default_headers(map)
                .build()
                .unwrap(),
            (None, None) => configured(ClientBuilder::new()).build().unwrap(),
        };

        let mut url = base_url;
        url.query_pairs_mut().append_pair("transport", "polling");

        PollingTransport {
            client: client.clone(),
            base_url: Arc::new(RwLock::new(url.clone())),
            generator: StreamGenerator::new(Self::stream(url, client)),
            queue: Arc::new(std::sync::Mutex::new(WriteQueue::default())),
        }
    }

    /// Queues one encoded packet without waiting; the returned receiver yields
    /// the outcome of the POST that carried it. Callers enqueue in send order.
    pub(crate) fn enqueue(&self, data: Bytes, is_binary_att: bool) -> oneshot::Receiver<SendResult> {
        let segment = if is_binary_att {
            // the binary attachment gets `base64` encoded
            let mut packet_bytes = BytesMut::with_capacity(data.len() + 1);
            packet_bytes.put_u8(b'b');
            let encoded_data = general_purpose::STANDARD.encode(data);
            packet_bytes.put(encoded_data.as_bytes());
            packet_bytes.freeze()
        } else {
            data
        };
        let (sender, receiver) = oneshot::channel();
        let start_writer = {
            let mut queue = self.queue.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            queue.pending.push_back((segment, sender));
            !std::mem::replace(&mut queue.writing, true)
        };
        if start_writer {
            let transport = self.clone();
            tokio::spawn(async move { transport.write_loop().await });
        }
        receiver
    }

    /// Sends queued packets, each POST carrying everything that is waiting.
    async fn write_loop(self) {
        loop {
            let batch = {
                let mut queue = self.queue.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                if queue.pending.is_empty() {
                    queue.writing = false;
                    return;
                }
                let mut size = 0;
                let mut batch = Vec::new();
                while let Some((segment, _)) = queue.pending.front() {
                    if !batch.is_empty() && size + 1 + segment.len() > MAX_BATCH_BYTES {
                        break;
                    }
                    size += segment.len() + usize::from(!batch.is_empty());
                    batch.push(queue.pending.pop_front().expect("front exists"));
                }
                batch
            };
            let mut body = BytesMut::with_capacity(batch.iter().map(|(segment, _)| segment.len() + 1).sum());
            for (index, (segment, _)) in batch.iter().enumerate() {
                if index > 0 {
                    body.put_u8(PAYLOAD_SEPARATOR);
                }
                body.put(segment.clone());
            }
            let result = self.post(body.freeze()).await.map_err(|error| error.to_string());
            for (_, sender) in batch {
                let _ = sender.send(result.clone());
            }
        }
    }

    async fn post(&self, body: Bytes) -> Result<()> {
        let address = self.address().await?;
        let post = || {
            self.client
                .post(address.clone())
                .timeout(POST_TIMEOUT + Duration::from_secs((body.len() / POST_BYTES_PER_EXTRA_SECOND) as u64))
                .body(body.clone())
        };
        // A failed connect never reached the server, so one retry cannot
        // deliver the packets twice.
        let response = match post().send().await {
            Ok(response) => response,
            Err(error) if error.is_connect() => post().send().await?,
            Err(error) => return Err(error.into()),
        };
        let status = response.status().as_u16();
        if status != 200 {
            return Err(Error::IncompleteHttp(status));
        }
        Ok(())
    }

    fn address(mut url: Url) -> Result<Url> {
        let reader = format!("{:#?}", SystemTime::now());
        let hash = adler32(reader.as_bytes()).unwrap();
        url.query_pairs_mut().append_pair("t", &hash.to_string());
        Ok(url)
    }

    fn send_request(url: Url, client: Client) -> impl Stream<Item = Result<Response>> {
        try_stream! {
            let address = Self::address(url);

            yield client
                .get(address?)
                .timeout(POLL_TIMEOUT)
                .send().await?
        }
    }

    fn stream(
        url: Url,
        client: Client,
    ) -> Pin<Box<dyn Stream<Item = Result<Bytes>> + 'static + Send>> {
        Box::pin(try_stream! {
            loop {
                for await elem in Self::send_request(url.clone(), client.clone()) {
                    for await bytes in elem?.bytes_stream() {
                        yield bytes?;
                    }
                }
            }
        })
    }
}

impl Stream for PollingTransport {
    type Item = Result<Bytes>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.generator.poll_next_unpin(cx)
    }
}

#[async_trait]
impl AsyncTransport for PollingTransport {
    async fn emit(&self, data: Bytes, is_binary_att: bool) -> Result<()> {
        self.enqueue(data, is_binary_att)
            .await
            .map_err(|_| Error::PollingSendFailed("polling writer stopped".to_string()))?
            .map_err(Error::PollingSendFailed)
    }

    async fn base_url(&self) -> Result<Url> {
        Ok(self.base_url.read().await.clone())
    }

    async fn set_base_url(&self, base_url: Url) -> Result<()> {
        let mut url = base_url;
        if !url
            .query_pairs()
            .any(|(k, v)| k == "transport" && v == "polling")
        {
            url.query_pairs_mut().append_pair("transport", "polling");
        }
        *self.base_url.write().await = url;
        Ok(())
    }
}

impl Debug for PollingTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PollingTransport")
            .field("client", &self.client)
            .field("base_url", &self.base_url)
            .finish()
    }
}

#[cfg(test)]
mod test {
    use crate::asynchronous::transport::AsyncTransport;

    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn polling_transport_base_url() -> Result<()> {
        let url = crate::test::engine_io_server()?.to_string();
        let transport = PollingTransport::new(Url::from_str(&url[..]).unwrap(), None, None);
        assert_eq!(
            transport.base_url().await?.to_string(),
            url.clone() + "?transport=polling"
        );
        transport
            .set_base_url(Url::parse("https://127.0.0.1")?)
            .await?;
        assert_eq!(
            transport.base_url().await?.to_string(),
            "https://127.0.0.1/?transport=polling"
        );
        assert_ne!(transport.base_url().await?.to_string(), url);

        transport
            .set_base_url(Url::parse("http://127.0.0.1/?transport=polling")?)
            .await?;
        assert_eq!(
            transport.base_url().await?.to_string(),
            "http://127.0.0.1/?transport=polling"
        );
        assert_ne!(transport.base_url().await?.to_string(), url);
        Ok(())
    }
}
