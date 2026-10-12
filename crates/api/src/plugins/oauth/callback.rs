use better_auth_core::utils::url::append_query_params;
use std::collections::HashMap;

use better_auth_core::{AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult};

use super::handlers::{
    FlowStartRequest, attach_cookie_state_payload, attach_state_cookie, auth_base_url,
    callback_user_request, complete_link_social, fetch_user_info_for_code,
    initiate_oauth_flow_core, redirect_response,
};
use super::provider_tokens::validate_authorization_code_via_provider;
use super::resolved::ResolvedOAuthConfig as OAuthConfig;
use super::signin::{OAuthSignInOptions, process_oauth_sign_in};
use super::state::{
    OAuthStatePayload, decode_cookie_state_value, decode_database_state_cookie_value, get_cookie,
    state_cookie_name,
};

pub(super) async fn handle_callback(
    config: &OAuthConfig,
    provider_name: &str,
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let default_error_url = ctx
        .config
        .api_error
        .error_url
        .clone()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| format!("{}/error", auth_base_url(ctx)));
    let meta = better_auth_core::RequestMeta::from_request_with_config(
        req,
        &ctx.config.advanced.ip_address,
    );

    let mut merged = HashMap::new();
    if req.method() == &better_auth_core::HttpMethod::Post {
        if let Some(body) = req.validated_body::<HashMap<String, String>>() {
            merged.extend(body.clone());
        } else {
            let body = parse_body(req)?;
            merged.extend(crate::plugins::query_input::string_map_value(body)?);
        }

        // Match the TS callback route: POST body seeds the redirect, but
        // explicit query parameters win over conflicting body fields.
        merged.extend(crate::plugins::query_input::string_map(req)?);

        let mut params = url::form_urlencoded::Serializer::new(String::new());
        let mut pairs: Vec<_> = merged.iter().collect();
        pairs.sort_by_key(|(left, _)| *left);
        for (key, value) in pairs {
            let _ = params.append_pair(key, value);
        }
        return Ok(redirect_response(&format!(
            "{}/callback/{}?{}",
            auth_base_url(ctx),
            provider_name,
            params.finish()
        )));
    }

    let merged = crate::plugins::query_input::string_map(req)?;

    let error = merged.get("error").cloned();
    let state_param =
        match merged.get("state").cloned() {
            Some(state) if !state.is_empty() => state,
            _ => {
                if !merged.contains_key("state")
                    && merged.get("code").is_some_and(|code| !code.is_empty())
                    && let Some(provider) = config.providers.get(provider_name)
                    && provider
                        .generic
                        .as_ref()
                        .is_some_and(|generic| generic.config.allow_idp_initiated)
                {
                    let flow = initiate_oauth_flow_core(
                        req,
                        ctx,
                        FlowStartRequest {
                            anonymous_user_id: None,
                            provider_name,
                            provider,
                            callback_url: super::handlers::state_callback_url(None, ctx)?,
                            new_user_callback_url: None,
                            error_callback_url: None,
                            scopes: None,
                            additional_params: None,
                            login_hint: None,
                            request_sign_up: None,
                            additional_data: Default::default(),
                            link: None,
                            disable_redirect: false,
                        },
                    )
                    .await?;
                    let response =
                        redirect_response(flow.response.url.as_deref().ok_or_else(|| {
                            AuthError::internal("Missing OAuth authorization URL")
                        })?);
                    return match ctx.config.account.store_state_strategy() {
                        better_auth_core::OAuthStateStrategy::Database => {
                            attach_state_cookie(response, &ctx.config, &flow.state)
                        }
                        better_auth_core::OAuthStateStrategy::Cookie => {
                            attach_cookie_state_payload(response, &ctx.config, &flow.payload)
                        }
                    };
                }
                return Ok(redirect_response(&append_query_params(
                    &default_error_url,
                    "error=state_not_found",
                )?));
            }
        };
    let expire_state_cookie = || {
        let cookie = better_auth_core::utils::cookie_utils::create_clear_cookie(
            &state_cookie_name(&ctx.config),
            &ctx.config,
        )?;
        req.append_response_header("Set-Cookie", cookie)
    };
    let payload = match ctx.config.account.store_state_strategy() {
        better_auth_core::OAuthStateStrategy::Database => {
            let verification = match ctx
                .database
                .get_verification_by_identifier(&state_param)
                .await?
            {
                Some(verification) => verification,
                None => {
                    return Ok(redirect_response(&append_query_params(
                        &default_error_url,
                        "error=state_mismatch",
                    )?));
                }
            };

            let payload = match OAuthStatePayload::parse(&verification.value.display_string()?) {
                Ok(payload) => payload,
                Err(_) => {
                    return Ok(redirect_response(&append_query_params(
                        &default_error_url,
                        "error=internal_server_error",
                    )?));
                }
            };
            let bound_state_matches = payload
                .oauth_state
                .as_deref()
                .is_none_or(|value| value == state_param);
            let cookie_matches = ctx.config.account.skip_state_cookie_check
                || get_cookie(req, &state_cookie_name(&ctx.config))
                    .and_then(|value| {
                        decode_database_state_cookie_value(ctx.config.signing_secret(), &value).ok()
                    })
                    .is_some_and(|value| value == state_param);
            if !bound_state_matches || !cookie_matches {
                return Ok(redirect_response(&append_query_params(
                    payload
                        .error_url
                        .as_deref()
                        .filter(|value| !value.is_empty())
                        .unwrap_or(&default_error_url),
                    "error=state_mismatch",
                )?));
            }
            expire_state_cookie()?;
            ctx.database
                .delete_verification_by_identifier(&state_param)
                .await?;
            payload
        }
        better_auth_core::OAuthStateStrategy::Cookie => {
            let Some(cookie_value) = get_cookie(req, &state_cookie_name(&ctx.config)) else {
                return Ok(redirect_response(&append_query_params(
                    &default_error_url,
                    "error=state_mismatch",
                )?));
            };
            match decode_cookie_state_value(ctx.config.encryption_secret(), &cookie_value) {
                Ok(payload) => {
                    if payload.oauth_state.as_deref() != Some(state_param.as_str()) {
                        return Ok(redirect_response(&append_query_params(
                            payload
                                .error_url
                                .as_deref()
                                .filter(|value| !value.is_empty())
                                .unwrap_or(&default_error_url),
                            "error=state_mismatch",
                        )?));
                    }
                    expire_state_cookie()?;
                    payload
                }
                Err(_) => {
                    return Ok(redirect_response(&append_query_params(
                        &default_error_url,
                        "error=state_invalid",
                    )?));
                }
            }
        }
    };

    let error_url = payload
        .error_url
        .clone()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default_error_url.clone());

    let error_location = |error_code: &str, description: Option<&str>| -> AuthResult<String> {
        let mut params = url::form_urlencoded::Serializer::new(String::new());
        let _ = params.append_pair("error", error_code);
        if let Some(description) = description {
            let _ = params.append_pair("error_description", description);
        }
        append_query_params(&error_url, &params.finish())
    };
    let redirect_on_error = |error_code: &str, description: Option<&str>| {
        Ok(redirect_response(&error_location(error_code, description)?))
    };

    if payload.is_expired() {
        return redirect_on_error("state_mismatch", None);
    }

    super::state_context::publish_parsed(req, &payload, Some(&default_error_url))?;

    if let Some(error) = error.as_deref().filter(|error| !error.is_empty()) {
        return redirect_on_error(
            error,
            merged
                .get("error_description")
                .map(String::as_str)
                .filter(|description| !description.is_empty()),
        );
    }

    if let Some(user_id) = payload.server_context.get("anonymousUserId") {
        req.set_server_context(
            "anonymousUserId",
            better_auth_core::FieldValue::from_json(user_id.clone())?,
        )?;
    }

    let Some(code) = merged.get("code").filter(|code| !code.is_empty()).cloned() else {
        return redirect_on_error("no_code", None);
    };

    let Some(provider) = config.providers.get(provider_name) else {
        return redirect_on_error("oauth_provider_not_found", None);
    };

    if let (Some(received), Some(expected)) = (
        merged.get("iss").filter(|value| !value.is_empty()),
        provider.issuer(),
    ) && received != expected
    {
        return redirect_on_error("issuer_mismatch", None);
    }
    if provider.requires_nonce() && payload.id_token_nonce.as_ref().is_none_or(String::is_empty) {
        return redirect_on_error("nonce_binding_missing", None);
    }

    let tokens = match validate_authorization_code_via_provider(
        provider,
        &code,
        &format!("{}/callback/{}", auth_base_url(ctx), provider_name),
        Some(&payload.code_verifier),
        merged.get("device_id").map(String::as_str),
    )
    .await
    {
        Ok(tokens) => tokens,
        Err(_) => return redirect_on_error("invalid_code", None),
    };

    let profile = fetch_user_info_for_code(
        provider,
        &tokens,
        callback_user_request(
            &tokens,
            merged.get("user").map(String::as_str),
            payload.id_token_nonce.as_deref(),
        )?,
        payload.id_token_nonce.as_deref(),
    )
    .await?;
    if !profile.value.is_truthy() || !profile.value.model_property("user")?.is_truthy() {
        return redirect_on_error("unable_to_get_user_info", None);
    }
    let user_info = profile.value.model_property("user")?;
    let provider_profile = profile.value.model_property("data")?;
    let account_id = match async {
        let data = profile.value.model_property("data")?;
        super::social_profile::resolve_account_subject(
            provider,
            &tokens,
            &data,
            profile.legacy_subject.as_ref(),
        )
        .await
    }
    .await
    {
        Ok(value) => value,
        Err(error) => {
            ctx.logger().error(
                "Unable to derive provider account identity",
                &[better_auth_core::observability::logger::LogArgument::Error(
                    &error,
                )],
            );
            return redirect_on_error("unable_to_get_user_info", None);
        }
    };

    let callback_body = if req.method() == &better_auth_core::HttpMethod::Post {
        serde_json::to_value(&merged)?
    } else {
        serde_json::Value::Null
    };
    let mut endpoint = crate::plugins::endpoint_context::EndpointContext::new(
        Some(req),
        better_auth_core::FieldValue::from_json(callback_body.clone())?,
        ctx,
    );
    endpoint.path = Some(super::signin::callback_path(req));
    let account = super::signin::token_account(provider_name, &account_id, &tokens)?;
    if let Some(link) = payload.link.as_ref() {
        if let super::handlers::OAuthLinkOutcome::Failed { code, description } =
            complete_link_social(
                &user_info,
                &account,
                &tokens.scopes,
                link,
                Some(&provider_profile),
                &endpoint,
            )
            .await?
        {
            return Err(req.redirect(error_location(&code, description.as_deref())?)?);
        }

        return Err(req.redirect(&payload.callback_url)?);
    }

    if !user_info.model_property("email")?.is_truthy() {
        return redirect_on_error("email_not_found", None);
    }
    let disable_sign_up = provider.config.disable_implicit_sign_up()
        && !payload.request_sign_up.unwrap_or(false)
        || provider.config.disable_sign_up();
    let outcome = match async {
        let user_info = super::native_user::callback_user(&user_info, account_id)?;
        process_oauth_sign_in(
            provider_name,
            provider,
            &user_info,
            &account,
            OAuthSignInOptions {
                request: req,
                profile: Some(&provider_profile),
                body: callback_body,
                disable_sign_up,
                override_user_info: provider.config.override_user_info_on_sign_in,
                callback_url: &payload.callback_url,
                email_verification: config.email_verification.as_deref(),
            },
            &meta,
            ctx,
        )
        .await
    }
    .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            let (code, description) = error.redirect_parts()?;
            return redirect_on_error(&code, description.as_deref());
        }
    };

    let redirect_target = if outcome.is_register {
        payload
            .new_user_url
            .as_deref()
            .unwrap_or(&payload.callback_url)
            .to_string()
    } else {
        payload.callback_url.clone()
    };
    ctx.session_manager()
        .set_native_session_cookie(req, outcome.issued, None)
        .await?;
    let response = redirect_response(&redirect_target);
    Ok(response)
}

fn parse_body(req: &AuthRequest) -> AuthResult<Option<serde_json::Value>> {
    let body = req.input_body()?;
    let Some(body) = body else {
        return Ok(None);
    };
    let object = body.as_object().ok_or_else(|| {
        crate::plugins::json_body::validation_error(&crate::plugins::json_body::invalid_type(
            "body",
            "object",
            Some(&body),
        ))
    })?;
    let mut output = serde_json::Map::new();
    let mut errors = Vec::new();
    for name in [
        "code",
        "error",
        "device_id",
        "error_description",
        "state",
        "user",
        "iss",
    ] {
        match object.get(name) {
            Some(value @ serde_json::Value::String(_)) => {
                let _ = output.insert(name.to_owned(), value.clone());
            }
            None => {}
            value => errors.push(crate::plugins::json_body::invalid_type(
                &format!("body.{name}"),
                "string",
                value,
            )),
        }
    }
    if !errors.is_empty() {
        return Err(crate::plugins::json_body::validation_error(
            &errors.join("; "),
        ));
    }
    Ok(Some(serde_json::Value::Object(output)))
}

pub(super) fn body(
    req: &AuthRequest,
) -> AuthResult<better_auth_core::endpoint_input::ValidatedBody> {
    let projection = parse_body(req)?;
    let typed = crate::plugins::query_input::string_map_value(projection.clone())?;
    Ok(better_auth_core::endpoint_input::ValidatedBody::new(
        projection, typed,
    ))
}
