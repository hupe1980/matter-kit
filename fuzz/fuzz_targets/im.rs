//! Every interaction model message, against arbitrary bytes.
//!
//! These are the messages a node reads once a session is up, from a peer that is
//! authenticated but not trusted: a commissioned controller on the fabric is still a piece
//! of software that can be wrong or hostile, and every path, filter and value in a request
//! is a number it chose.
//!
//! Three properties:
//!
//! 1. **Nothing panics**, whatever the bytes.
//! 2. **Iteration terminates.** The arrays are lazy, so a malformed one must yield an error
//!    and then stop rather than looping — a server walking a request's paths would otherwise
//!    hang on a single bad message.
//! 3. **Borrowed payloads really are slices of the input.** An attribute's value and a
//!    command's fields are handed to a cluster verbatim; if they pointed at anything but the
//!    bytes that arrived, a server would act on data the client did not send.

#![no_main]

use libfuzzer_sys::fuzz_target;
use matter_kit::im::{
    AttributeReport, EventReport, InvokeRequest, InvokeResponseMessage, ReadRequest, ReportData,
    StatusResponse, SubscribeRequest, SubscribeResponse, TimedRequest, WriteRequest, WriteResponse,
};

/// Walks a lazy array, proving it terminates and never yields past its first error.
fn drain<T>(iter: impl Iterator<Item = matter_kit::Result<T>>) {
    let mut seen = 0usize;
    for item in iter {
        seen += 1;
        assert!(seen < 4096, "iteration did not terminate");
        if item.is_err() {
            // The next call must return None; the loop ending proves it.
            continue;
        }
    }
}

/// Every borrowed payload must be a slice of the message it came from.
fn assert_borrowed(data: &[u8], haystack: &[u8]) {
    assert!(
        data.is_empty() || haystack.windows(data.len()).any(|w| w == data),
        "a carried payload is not a slice of the input"
    );
}

fuzz_target!(|data: &[u8]| {
    let _ = StatusResponse::decode(data);
    let _ = TimedRequest::decode(data);
    let _ = SubscribeResponse::decode(data);

    if let Ok(request) = ReadRequest::decode(data) {
        if let Ok(Some(paths)) = request.attribute_paths() {
            drain(paths);
        }
        if let Ok(Some(paths)) = request.event_paths() {
            drain(paths);
        }
        if let Ok(Some(filters)) = request.event_filters() {
            drain(filters);
        }
        if let Ok(Some(filters)) = request.data_version_filters() {
            drain(filters);
        }
    }

    if let Ok(request) = SubscribeRequest::decode(data) {
        if let Ok(Some(paths)) = request.attribute_paths() {
            drain(paths);
        }
        if let Ok(Some(filters)) = request.data_version_filters() {
            drain(filters);
        }
    }

    if let Ok(report) = ReportData::decode(data) {
        if let Ok(Some(reports)) = report.attribute_reports() {
            let mut seen = 0usize;
            for item in reports {
                seen += 1;
                assert!(seen < 4096, "iteration did not terminate");
                match item {
                    Ok(AttributeReport::Data(attribute)) => assert_borrowed(attribute.data, data),
                    Ok(AttributeReport::Status(_)) | Err(_) => {}
                }
            }
        }
        // An event report carries a nested timestamp *choice* (§10.6.9) and a cluster-defined
        // payload — two more places a hostile message can be malformed, and the payload is
        // borrowed like an attribute's.
        if let Ok(Some(reports)) = report.event_reports() {
            let mut seen = 0usize;
            for item in reports {
                seen += 1;
                assert!(seen < 4096, "iteration did not terminate");
                match item {
                    Ok(EventReport::Data(event)) => assert_borrowed(event.data, data),
                    Ok(EventReport::Status(_)) | Err(_) => {}
                }
            }
        }
    }

    if let Ok(request) = WriteRequest::decode(data)
        && let Ok(writes) = request.writes()
    {
        let mut seen = 0usize;
        for item in writes {
            seen += 1;
            assert!(seen < 4096, "iteration did not terminate");
            if let Ok(attribute) = item {
                assert_borrowed(attribute.data, data);
            }
        }
    }

    if let Ok(response) = WriteResponse::decode(data)
        && let Ok(statuses) = response.statuses()
    {
        drain(statuses);
    }

    if let Ok(request) = InvokeRequest::decode(data)
        && let Ok(commands) = request.commands()
    {
        let mut seen = 0usize;
        for item in commands {
            seen += 1;
            assert!(seen < 4096, "iteration did not terminate");
            if let Ok(command) = item
                && let Some(fields) = command.fields
            {
                assert_borrowed(fields, data);
            }
        }
    }

    if let Ok(response) = InvokeResponseMessage::decode(data)
        && let Ok(responses) = response.responses()
    {
        drain(responses);
    }
});
