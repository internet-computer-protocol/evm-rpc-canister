use crate::http_types::HttpRequest;

#[test]
fn test_raw_query_param() {
    fn request_with_url(url: String) -> HttpRequest {
        HttpRequest {
            method: "".to_string(),
            url,
            headers: vec![],
            body: Default::default(),
        }
    }
    let http_request = request_with_url("/endpoint?time=1000".to_string());
    assert_eq!(http_request.raw_query_param("time"), Some("1000"));
    let http_request = request_with_url("/endpoint".to_string());
    assert_eq!(http_request.raw_query_param("time"), None);
    let http_request =
        request_with_url("/endpoint?time=1000&time=1001&other=abcde&time=1002".to_string());
    assert_eq!(http_request.raw_query_param("time"), Some("1000"));
}
