//! Integration test for a custom / local OpenAI-compatible endpoint.
//!
//! A local model server (Ollama, LM Studio, llama.cpp, vLLM, …) speaks the same
//! `/chat/completions` shape but usually requires no API key. These tests run a
//! throwaway HTTP server on loopback and assert that the client calls the
//! configured endpoint and omits the `Authorization` header when the key is
//! empty.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};
use std::net::TcpListener;

use recurse_agent::agent::{complete_http, ChatMessage};

/// Minimal user turn (the constructor is internal to the crate).
fn user(content: &str) -> ChatMessage {
    ChatMessage {
        role: "user".into(),
        content: Some(content.to_string()),
        tool_calls: None,
        tool_call_id: None,
        reasoning: None,
    }
}

/// One-shot HTTP/1.1 server: accept a single request, capture whether it
/// carried an `Authorization` header, and reply with a canned completion body.
/// Returns a join handle yielding `true` when the header was present.
fn mock_completion_server() -> (String, std::thread::JoinHandle<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let mut buf = [0u8; 16 * 1024];
        let n = sock.read(&mut buf).unwrap();
        let request = String::from_utf8_lossy(&buf[..n]).to_lowercase();
        let had_auth = request.contains("\nauthorization:") || request.contains("authorization:");
        let body = r#"{"choices":[{"message":{"role":"assistant","content":"local-ok"}}]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        sock.write_all(response.as_bytes()).unwrap();
        sock.flush().unwrap();
        had_auth
    });
    (format!("http://{addr}/v1/chat/completions"), handle)
}

#[tokio::test]
async fn keyless_local_endpoint_gets_no_authorization_header() {
    let (url, server) = mock_completion_server();
    let out = complete_http(&url, "", "llama3.1:8b", &[user("hi")])
        .await
        .unwrap();
    assert_eq!(out, "local-ok");
    assert!(
        !server.join().unwrap(),
        "a keyless endpoint must not receive an Authorization header"
    );
}

#[tokio::test]
async fn configured_key_is_sent_as_bearer() {
    let (url, server) = mock_completion_server();
    let out = complete_http(&url, "secret-key", "remote", &[user("hi")])
        .await
        .unwrap();
    assert_eq!(out, "local-ok");
    assert!(
        server.join().unwrap(),
        "a configured key must be sent as an Authorization header"
    );
}
