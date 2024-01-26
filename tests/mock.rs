use std::collections::HashSet;

use ic_cdk::api::management_canister::http_request::{
    CanisterHttpRequestArgument, HttpHeader, HttpMethod, HttpResponse,
};

pub struct MockOutcallBody(pub Vec<u8>);

impl From<String> for MockOutcallBody {
    fn from(string: String) -> Self {
        string.as_bytes().to_vec().into()
    }
}
impl<'a> From<&'a str> for MockOutcallBody {
    fn from(string: &'a str) -> Self {
        string.to_string().into()
    }
}
impl From<Vec<u8>> for MockOutcallBody {
    fn from(bytes: Vec<u8>) -> Self {
        MockOutcallBody(bytes)
    }
}

#[derive(Clone, Debug)]
pub struct MockOutcallBuilder(MockOutcall);

impl MockOutcallBuilder {
    pub fn new(status: u16, body: impl Into<MockOutcallBody>) -> Self {
        Self(MockOutcall {
            method: None,
            url: None,
            request_headers: None,
            request_body: None,
            max_response_bytes: None,
            response: HttpResponse {
                status: status.into(),
                headers: vec![],
                body: body.into().0,
            },
        })
    }

    pub fn with_method(mut self, method: HttpMethod) -> Self {
        self.0.method = Some(method);
        self
    }

    pub fn with_url(mut self, url: impl ToString) -> Self {
        self.0.url = Some(url.to_string());
        self
    }

    pub fn with_request_headers(mut self, headers: Vec<(impl ToString, impl ToString)>) -> Self {
        self.0.request_headers = Some(
            headers
                .into_iter()
                .map(|(name, value)| HttpHeader {
                    name: name.to_string(),
                    value: value.to_string(),
                })
                .collect(),
        );
        self
    }

    pub fn with_request_body(mut self, body: impl Into<MockOutcallBody>) -> Self {
        self.0.request_body = Some(body.into().0);
        self
    }

    pub fn with_max_response_bytes(mut self, max_response_bytes: u64) -> Self {
        self.0.max_response_bytes = Some(max_response_bytes);
        self
    }

    pub fn with_response_header(mut self, name: String, value: String) -> Self {
        self.0.response.headers.push(HttpHeader { name, value });
        self
    }

    pub fn build(self) -> MockOutcall {
        self.0
    }
}

impl From<MockOutcallBuilder> for MockOutcall {
    fn from(builder: MockOutcallBuilder) -> Self {
        builder.build()
    }
}

#[derive(Clone, Debug)]
pub struct MockOutcall {
    pub method: Option<HttpMethod>,
    pub url: Option<String>,
    pub request_headers: Option<Vec<HttpHeader>>,
    pub request_body: Option<Vec<u8>>,
    pub max_response_bytes: Option<u64>,
    pub response: HttpResponse,
}

impl MockOutcall {
    pub fn assert_matches(&self, request: &CanisterHttpRequestArgument) {
        if let Some(ref url) = self.url {
            assert_eq!(url, &request.url);
        }
        if let Some(ref method) = self.method {
            assert_eq!(method, &request.method);
        }
        if let Some(ref headers) = self.request_headers {
            assert_eq!(
                headers.iter().collect::<HashSet<_>>(),
                request.headers.iter().collect::<HashSet<_>>()
            );
        }
        if let Some(ref body) = self.request_body {
            assert_eq!(body, &request.body.as_deref().unwrap_or_default());
        }
        if let Some(max_response_bytes) = self.max_response_bytes {
            assert_eq!(Some(max_response_bytes), request.max_response_bytes);
        }
    }
}

impl From<HttpResponse> for MockOutcall {
    fn from(response: HttpResponse) -> Self {
        Self {
            method: None,
            url: None,
            request_headers: None,
            request_body: None,
            max_response_bytes: None,
            response,
        }
    }
}
