use super::http_init::{HttpInit, copy_headers, headers_init, nullish, optional_property};
use crate::{AuthResponse, AuthResult, FieldObject, FieldValue, Headers, ResponseBody};

impl AuthResponse {
    pub(super) fn materialize_json_wrapper(
        &mut self,
        fields: &FieldObject,
        init: HttpInit,
    ) -> AuthResult<()> {
        let body = fields.get("body")?.unwrap_or_default();
        let router = fields.get("routerResponse")?.unwrap_or_default();
        let mut headers = Headers::new();
        copy_headers(&mut headers, &optional_property(&router, "headers")?)?;
        copy_headers(&mut headers, &fields.get("headers")?.unwrap_or_default())?;
        if init.headers.is_truthy() {
            let mut safe_headers = headers_init(&init.headers)?;
            safe_headers.strip_request_only();
            headers.merge(safe_headers);
        }
        let _ = headers.insert("content-type", "application/json");

        // JSON runs before ResponseInit spread, including getters whose values are later overwritten.
        let body = body.stringify()?.map_or(ResponseBody::Empty, |text| {
            ResponseBody::Bytes(text.into_bytes())
        });
        let router_init = router.enumerable_fields()?;
        let mut status = fields.get("status")?.unwrap_or_default();
        if nullish(&status) {
            status = init.status;
        }
        if nullish(&status) {
            status = optional_property(&router, "status")?;
        }
        let status_text = if nullish(&init.status_text) {
            optional_property(&router, "statusText")?
        } else {
            init.status_text
        };
        self.apply_http_init(&status, &status_text)?;
        if let Some(method) = router_init.get("method")
            && method.is_truthy()
        {
            let _ = method.display_utf16()?;
        }
        self.headers = headers;
        self.body = body;
        Ok(())
    }
}
