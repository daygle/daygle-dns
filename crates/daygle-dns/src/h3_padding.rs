//! EDNS padding (RFC 8467) for DNS over HTTP/3.
//!
//! Hickory's HTTP/3 listener encodes the message itself and keeps the
//! encoded bytes private, so a padding request cannot be answered the way the
//! DoH (HTTP/2) and DoQ listeners do it, at the point where the bytes are
//! written. Instead this wrapper sits between the dispatcher and Hickory's
//! responder: it re-reads the encoded answer, adds the EDNS(0) Padding option
//! and sends the result, which Hickory then puts on the HTTP/3 stream.
//!
//! Only unsigned ordinary queries are wrapped (see [`wants_padding`]): a
//! TSIG-signed message cannot be re-encoded without breaking its MAC.

use async_trait::async_trait;
use hickory_proto::op::{Edns, Header, Message, OpCode};
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use hickory_proto::rr::Record;
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncoder};
use hickory_server::net::xfer::Protocol;
use hickory_server::net::NetError;
use hickory_server::server::{Request, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::{MessageResponse, MessageResponseBuilder, Queries};

use crate::dot::PADDING_BLOCK;

/// Whether this request needs the HTTP/3 padding wrapper: a padded (RFC 8467)
/// unsigned query over HTTP/3.
pub(crate) fn wants_padding(request: &Request) -> bool {
    request.protocol() == Protocol::H3
        && request.metadata.op_code == OpCode::Query
        && request.signature.is_none()
        && request
            .edns
            .as_ref()
            .is_some_and(|edns| edns.option(EdnsCode::Padding).is_some())
}

/// A response rebuilt from a parsed message, borrowing its records.
type RebuiltResponse<'q, 'a> = MessageResponse<
    'q,
    'a,
    std::slice::Iter<'a, Record>,
    std::slice::Iter<'a, Record>,
    std::iter::Empty<&'a Record>,
    std::slice::Iter<'a, Record>,
>;

/// Rebuild a response from a parsed message, with `edns` as its OPT record.
fn rebuild<'q, 'a>(
    message: &'a Message,
    queries: &'q Queries,
    edns: Option<&'q Edns>,
) -> RebuiltResponse<'q, 'a> {
    MessageResponseBuilder::new(queries, edns).build(
        message.metadata,
        message.answers.iter(),
        message.authorities.iter(),
        std::iter::empty::<&Record>(),
        message.additionals.iter(),
    )
}

/// Encode a rebuilt response, to measure what will be sent.
fn measured(
    message: &Message,
    queries: &Queries,
    edns: Option<&Edns>,
) -> Result<Vec<u8>, NetError> {
    let mut bytes = Vec::with_capacity(512);
    let mut encoder = BinEncoder::new(&mut bytes);
    encoder.set_max_size(u16::MAX);
    rebuild(message, queries, edns)
        .destructive_emit(&mut encoder)
        .map_err(|_| NetError::Message("cannot encode the HTTP/3 response"))?;
    Ok(bytes)
}

/// The queries of an encoded message, as Hickory's responder expects them.
fn queries_of(bytes: &[u8]) -> Option<Queries> {
    let mut decoder = BinDecoder::new(bytes);
    let header = Header::read(&mut decoder).ok()?;
    Queries::read(&mut decoder, header.counts.queries as usize).ok()
}

/// Pads the answers of a padded HTTP/3 query, then hands them to Hickory's
/// own responder.
#[derive(Clone)]
pub(crate) struct H3PadResponder<R> {
    inner: R,
}

impl<R> H3PadResponder<R> {
    pub(crate) fn new(inner: R) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl<R: ResponseHandler> ResponseHandler for H3PadResponder<R> {
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> Result<ResponseInfo, NetError> {
        let mut bytes = Vec::with_capacity(512);
        {
            let mut encoder = BinEncoder::new(&mut bytes);
            encoder.set_max_size(u16::MAX);
            response
                .destructive_emit(&mut encoder)
                .map_err(|_| NetError::Message("cannot encode the HTTP/3 response"))?;
        }

        let message = Message::from_vec(&bytes)
            .map_err(|_| NetError::Message("cannot re-read the HTTP/3 response"))?;
        if message.signature.is_some() {
            return Err(NetError::Message(
                "cannot pad a TSIG-signed HTTP/3 response",
            ));
        }
        let queries =
            queries_of(&bytes).ok_or(NetError::Message("cannot re-read the HTTP/3 queries"))?;

        // RFC 8467 padding lives in an OPT record: without one (the client
        // did not send EDNS) the answer goes out unchanged.
        let Some(mut edns) = message.edns.clone() else {
            return self
                .inner
                .send_response(rebuild(&message, &queries, None))
                .await;
        };
        edns.options_mut().remove(EdnsCode::Padding);

        // Measure the answer as it will be sent, plus the option's own
        // 4-octet header, and pad it to the next block.
        let unpadded = measured(&message, &queries, Some(&edns))?;
        let len = unpadded.len() + 4;
        let pad = (PADDING_BLOCK - len % PADDING_BLOCK) % PADDING_BLOCK;
        if len + pad <= u16::MAX as usize {
            edns.options_mut().insert(EdnsOption::Unknown(
                u16::from(EdnsCode::Padding),
                vec![0; pad],
            ));
        }
        self.inner
            .send_response(rebuild(&message, &queries, Some(&edns)))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, Metadata, Query};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, RecordType};
    use std::sync::{Arc, Mutex};

    /// Collects the encoded response it is given.
    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Option<Vec<u8>>>>);

    #[async_trait]
    impl ResponseHandler for Capture {
        async fn send_response<'a>(
            &mut self,
            response: MessageResponse<
                '_,
                'a,
                impl Iterator<Item = &'a Record> + Send + 'a,
                impl Iterator<Item = &'a Record> + Send + 'a,
                impl Iterator<Item = &'a Record> + Send + 'a,
                impl Iterator<Item = &'a Record> + Send + 'a,
            >,
        ) -> Result<ResponseInfo, NetError> {
            let mut bytes = Vec::new();
            let mut encoder = BinEncoder::new(&mut bytes);
            encoder.set_max_size(u16::MAX);
            let info = response.destructive_emit(&mut encoder)?;
            *self.0.lock().unwrap() = Some(bytes);
            Ok(info)
        }
    }

    /// A query over `protocol`, asking for EDNS padding when `padded`.
    fn request(protocol: Protocol, padded: bool) -> Request {
        let mut message = Message::new(7, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        let mut edns = Edns::new();
        if padded {
            edns.options_mut().insert(EdnsOption::Unknown(
                u16::from(EdnsCode::Padding),
                Vec::new(),
            ));
        }
        message.edns = Some(edns);
        Request::from_bytes(
            message.to_vec().unwrap(),
            "192.0.2.1:443".parse().unwrap(),
            protocol,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn pads_h3_answers_to_the_block_length() {
        let request = request(Protocol::H3, true);
        let answer = Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            60,
            RData::A(A::new(192, 0, 2, 10)),
        );
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        let response = MessageResponseBuilder::new(&request.queries, Some(&edns)).build(
            Metadata::new(7, MessageType::Response, OpCode::Query),
            [&answer],
            [],
            [],
            [],
        );

        let capture = Capture::default();
        let mut responder = H3PadResponder::new(capture.clone());
        responder.send_response(response).await.unwrap();
        let bytes = capture
            .0
            .lock()
            .unwrap()
            .clone()
            .expect("a response was sent");

        assert_eq!(bytes.len() % PADDING_BLOCK, 0, "{} octets", bytes.len());
        let message = Message::from_vec(&bytes).unwrap();
        assert_eq!(message.metadata.id, 7);
        assert_eq!(message.answers.len(), 1);
        assert!(message
            .edns
            .as_ref()
            .and_then(|e| e.option(EdnsCode::Padding))
            .is_some());
    }

    #[test]
    fn only_padded_h3_queries_are_wrapped() {
        assert!(wants_padding(&request(Protocol::H3, true)));
        for protocol in [Protocol::Https, Protocol::Tcp, Protocol::Udp] {
            assert!(!wants_padding(&request(protocol, true)));
        }
        assert!(!wants_padding(&request(Protocol::H3, false)));
    }
}
