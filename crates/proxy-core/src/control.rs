use std::{collections::BTreeMap, io, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::{
    net::TcpListener,
    sync::{Semaphore, watch},
    time::timeout,
};

use crate::routing::{ProxyGroupSnapshot, RuleError, RuleSet};

const MAX_REQUEST_BODY_BYTES: usize = 4 * 1024;
const MAX_CONCURRENT_REQUESTS: usize = 32;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
struct ControllerState {
    routing: watch::Receiver<Arc<RuleSet>>,
    secret: Arc<str>,
    request_slots: Arc<Semaphore>,
}

#[derive(Debug, Serialize)]
struct ProxyGroupStatus {
    name: String,
    #[serde(rename = "type")]
    kind: &'static str,
    now: String,
    all: Vec<String>,
    history: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct ProxiesResponse {
    proxies: BTreeMap<String, ProxyGroupStatus>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectRequest {
    name: String,
}

/// Serve the loopback-only, Bearer-authenticated subset of the proxy control API.
pub async fn serve(
    listener: TcpListener,
    routing: watch::Receiver<Arc<RuleSet>>,
    secret: String,
) -> io::Result<()> {
    let state = ControllerState {
        routing,
        secret: Arc::from(secret),
        request_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS)),
    };
    let app = Router::new()
        .route("/proxies", get(list_proxy_groups))
        .route(
            "/proxies/{name}",
            get(get_proxy_group).put(select_proxy_group),
        )
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            authorize_request,
        ))
        .with_state(state);
    axum::serve(listener, app).await.map_err(io::Error::other)
}

async fn authorize_request(
    State(state): State<ControllerState>,
    request: Request,
    next: Next,
) -> Response {
    if !has_valid_bearer_token(request.headers(), &state.secret) {
        return error_response(StatusCode::UNAUTHORIZED, "missing or invalid bearer token");
    }
    let Ok(_permit) = state.request_slots.clone().try_acquire_owned() else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "too many control requests");
    };
    match timeout(REQUEST_TIMEOUT, next.run(request)).await {
        Ok(response) => response,
        Err(_) => error_response(StatusCode::GATEWAY_TIMEOUT, "control request timed out"),
    }
}

fn has_valid_bearer_token(headers: &HeaderMap, expected: &str) -> bool {
    let Some(value) = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let Some((scheme, candidate)) = value.split_once(' ') else {
        return false;
    };
    scheme.eq_ignore_ascii_case("Bearer")
        && !candidate.is_empty()
        && fixed_bound_equal(candidate.as_bytes(), expected.as_bytes())
}

fn fixed_bound_equal(candidate: &[u8], expected: &[u8]) -> bool {
    // Config validation caps the expected secret at 256 bytes. Keep the work
    // independent of the candidate length, including overlong credentials.
    let mut difference = candidate.len() ^ expected.len();
    for index in 0..256 {
        let left = candidate.get(index).copied().unwrap_or_default();
        let right = expected.get(index).copied().unwrap_or_default();
        difference |= usize::from(left ^ right);
    }
    difference == 0
}

async fn list_proxy_groups(State(state): State<ControllerState>) -> Json<ProxiesResponse> {
    let rules = Arc::clone(&state.routing.borrow());
    let proxies = rules
        .proxy_group_snapshots()
        .into_iter()
        .map(|group| (group.name.clone(), ProxyGroupStatus::from(group)))
        .collect();
    Json(ProxiesResponse { proxies })
}

async fn get_proxy_group(
    State(state): State<ControllerState>,
    Path(name): Path<String>,
) -> Response {
    let rules = Arc::clone(&state.routing.borrow());
    match rules.proxy_group_snapshot(&name) {
        Some(group) => Json(ProxyGroupStatus::from(group)).into_response(),
        None => error_response(StatusCode::NOT_FOUND, "proxy group not found"),
    }
}

async fn select_proxy_group(
    State(state): State<ControllerState>,
    Path(group): Path<String>,
    Json(selection): Json<SelectRequest>,
) -> Response {
    let rules = Arc::clone(&state.routing.borrow());
    match rules.select_proxy_group_member(&group, &selection.name) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(RuleError::UnknownProxyGroup { .. }) => {
            error_response(StatusCode::NOT_FOUND, "proxy group not found")
        }
        Err(RuleError::InvalidProxyGroupMember { .. }) => error_response(
            StatusCode::BAD_REQUEST,
            "member is not configured in this group",
        ),
        Err(_) => error_response(StatusCode::BAD_REQUEST, "invalid proxy group selection"),
    }
}

fn error_response(status: StatusCode, message: &'static str) -> Response {
    (status, Json(json!({ "message": message }))).into_response()
}

impl From<ProxyGroupSnapshot> for ProxyGroupStatus {
    fn from(group: ProxyGroupSnapshot) -> Self {
        Self {
            name: group.name,
            kind: "Selector",
            now: group.selected,
            all: group.members,
            history: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Config, RequestTarget, RouteAction, TargetHost};
    use serde_json::Value;
    use tokio::{task::JoinHandle, time::sleep};

    const TEST_SECRET: &str = "test-control-secret";

    async fn start_controller(
        rules: RuleSet,
    ) -> (
        String,
        JoinHandle<io::Result<()>>,
        watch::Receiver<Arc<RuleSet>>,
    ) {
        let (sender, receiver) = watch::channel(Arc::new(rules));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(serve(listener, receiver.clone(), TEST_SECRET.to_owned()));
        (format!("http://{address}"), server, sender.subscribe())
    }

    fn group_config() -> Config {
        Config::from_yaml_str(
            "proxy-groups:\n  - { name: selected, type: select, proxies: [DIRECT, REJECT] }\nrules:\n  - MATCH,selected\n",
        )
        .unwrap()
    }

    async fn wait_for_server() {
        sleep(Duration::from_millis(20)).await;
    }

    #[tokio::test]
    async fn lists_and_selects_group_members_used_by_live_routing() {
        let config = group_config();
        let (base_url, server, routing) = start_controller(config.routing_rules().unwrap()).await;
        wait_for_server().await;
        let client = reqwest::Client::new();
        let response = client
            .get(format!("{base_url}/proxies"))
            .bearer_auth(TEST_SECRET)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let listing: Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
        assert_eq!(listing["proxies"]["selected"]["type"], "Selector");
        assert_eq!(listing["proxies"]["selected"]["now"], "DIRECT");
        assert_eq!(listing["proxies"]["selected"]["all"][0], "DIRECT");

        let response = client
            .put(format!("{base_url}/proxies/selected"))
            .bearer_auth(TEST_SECRET)
            .header("content-type", "application/json")
            .body(r#"{"name":"REJECT"}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let target = RequestTarget {
            host: TargetHost::Domain("example.org".to_owned()),
            port: 443,
        };
        assert_eq!(routing.borrow().route(&target), RouteAction::Reject);

        let response = client
            .get(format!("{base_url}/proxies/selected"))
            .bearer_auth(TEST_SECRET)
            .send()
            .await
            .unwrap();
        let status: Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
        assert_eq!(status["now"], "REJECT");
        server.abort();
    }

    #[tokio::test]
    async fn rejects_unauthorized_and_invalid_selections_without_changing_state() {
        let config = group_config();
        let (base_url, server, routing) = start_controller(config.routing_rules().unwrap()).await;
        wait_for_server().await;
        let client = reqwest::Client::new();
        let response = client
            .put(format!("{base_url}/proxies/selected"))
            .header("content-type", "application/json")
            .body(r#"{"name":"REJECT"}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = client
            .put(format!("{base_url}/proxies/selected"))
            .bearer_auth(TEST_SECRET)
            .header("content-type", "application/json")
            .body(r#"{"name":"missing"}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response = client
            .put(format!("{base_url}/proxies/unknown"))
            .bearer_auth(TEST_SECRET)
            .header("content-type", "application/json")
            .body(r#"{"name":"DIRECT"}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            routing.borrow().route(&RequestTarget {
                host: TargetHost::Domain("example.org".to_owned()),
                port: 443,
            }),
            RouteAction::Direct
        );
        server.abort();
    }

    #[tokio::test]
    async fn rejects_oversized_and_unrecognized_json_without_changing_state() {
        let config = group_config();
        let (base_url, server, routing) = start_controller(config.routing_rules().unwrap()).await;
        wait_for_server().await;
        let client = reqwest::Client::new();

        let response = client
            .put(format!("{base_url}/proxies/selected"))
            .bearer_auth(TEST_SECRET)
            .header("content-type", "application/json")
            .body(vec![b' '; MAX_REQUEST_BODY_BYTES + 1])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let response = client
            .put(format!("{base_url}/proxies/selected"))
            .bearer_auth(TEST_SECRET)
            .header("content-type", "application/json")
            .body(r#"{"name":"REJECT","unexpected":true}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            routing.borrow().route(&RequestTarget {
                host: TargetHost::Domain("example.org".to_owned()),
                port: 443,
            }),
            RouteAction::Direct
        );
        server.abort();
    }

    #[tokio::test]
    async fn aborting_controller_releases_its_loopback_listener() {
        let (_, routing) = watch::channel(Arc::new(RuleSet::default()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(serve(listener, routing, TEST_SECRET.to_owned()));

        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
        let rebound = TcpListener::bind(address).await.unwrap();
        drop(rebound);
    }

    #[test]
    fn bearer_comparison_accepts_case_insensitive_scheme_and_compares_lengths() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "bEaReR secret".parse().unwrap());
        assert!(has_valid_bearer_token(&headers, "secret"));
        headers.insert(AUTHORIZATION, "Bearer secret-extra".parse().unwrap());
        assert!(!has_valid_bearer_token(&headers, "secret"));
        headers.insert(AUTHORIZATION, "Bearer secret".parse().unwrap());
        assert!(!has_valid_bearer_token(&headers, "secret-longer"));
    }
}
