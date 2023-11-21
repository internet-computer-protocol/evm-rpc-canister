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

pub struct MockOutcallBuilder(MockOutcall);

impl MockOutcallBuilder {
    pub fn new(status: u16, body: impl Into<MockOutcallBody>) -> Self {
        Self(MockOutcall {
            method: None,
            url: None,
            request_headers: None,
            request_body: None,
            response: HttpResponse {
                status: status.into(),
                headers: vec![],
                body: body.into().0,
            },
        })
    }

    pub fn expect_method(mut self, method: HttpMethod) -> Self {
        self.0.method = Some(method);
        self
    }

    pub fn expect_url(mut self, url: impl ToString) -> Self {
        self.0.url = Some(url.to_string());
        self
    }

    pub fn expect_headers(mut self, headers: Vec<HttpHeader>) -> Self {
        self.0.request_headers = Some(headers);
        self
    }

    pub fn expect_body(mut self, body: impl Into<MockOutcallBody>) -> Self {
        self.0.request_body = Some(body.into().0);
        self
    }

    pub fn build(self) -> MockOutcall {
        self.0
    }
}

#[derive(Clone, Debug)]
pub struct MockOutcall {
    pub method: Option<HttpMethod>,
    pub url: Option<String>,
    pub request_headers: Option<Vec<HttpHeader>>,
    pub request_body: Option<Vec<u8>>,
    pub response: HttpResponse,
}

impl MockOutcall {
    pub fn assert_matches(&self, request: &CanisterHttpRequestArgument) {
        if let Some(ref url) = self.url {
            assert_eq!(url, &request.url);
        }
        if let Some(ref headers) = self.request_headers {
            assert_eq!(headers, &request.headers);
        }
        if let Some(ref body) = self.request_body {
            assert_eq!(body, &request.body.as_deref().unwrap_or_default());
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
            response,
        }
    }
}
