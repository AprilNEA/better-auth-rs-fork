use super::ApiKeyPlugin;
use better_auth_core::{
    AuthContext, AuthResponse, AuthResult, AuthRoute, AuthSchema, FieldMap, FieldValue, HttpMethod,
    NativeRequest, observability::LogArgument,
};

impl ApiKeyPlugin {
    /// Run the registered server-only cleanup endpoint and retain its complete native result.
    pub async fn delete_all_expired_api_keys(
        &self,
        context: &AuthContext<impl AuthSchema>,
        source: NativeRequest<'_>,
        body: FieldValue,
        query: FieldValue,
    ) -> AuthResult<FieldValue> {
        let response = context
            .dispatch_native_value(
                source,
                AuthRoute::server_only(HttpMethod::Post, "deleteAllExpiredApiKeys"),
                body,
                query,
                |_, context| async move {
                    let cleanup =
                        self.maybe_delete_expired(&context, true)
                            .await
                            .or_else(|error| {
                                context.logger().error(
                                    "Failed to delete expired API keys:",
                                    &[LogArgument::Error(&error)],
                                )
                            });
                    let (success, error) = match cleanup {
                        Ok(()) => (true, FieldValue::Null),
                        Err(error) => {
                            context.logger().error(
                                "[API KEY PLUGIN] Failed to delete expired API keys:",
                                &[LogArgument::Error(&error)],
                            )?;
                            (false, error.into_thrown_value()?)
                        }
                    };
                    Ok(AuthResponse::native(
                        None,
                        FieldMap::from([
                            ("success".into(), success.into()),
                            ("error".into(), error),
                        ])
                        .into(),
                    ))
                },
            )
            .await?;
        response.body.field_value()
    }
}
