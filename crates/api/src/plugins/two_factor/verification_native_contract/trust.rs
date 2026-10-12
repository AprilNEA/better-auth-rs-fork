use super::*;
use better_auth_core::FromFieldMap;

pub(super) async fn capture(scenario: &Json) -> AuthResult<Json> {
    let identifier = "trust-device-native";
    let harness = Harness::new(scenario, identifier)?;
    let plugin = TwoFactorPlugin::new();
    let (context, inner) = harness.context(&[&plugin]).await?;
    let session = FieldMap::from([
        ("id".into(), "new-session-id".into()),
        ("token".into(), "new-session".into()),
        ("userId".into(), "owner".into()),
        ("createdAt".into(), date(NOW as f64)),
        ("updatedAt".into(), date(NOW as f64)),
        ("expiresAt".into(), date((NOW + 60_000) as f64)),
        ("ipAddress".into(), FieldValue::Null),
        ("userAgent".into(), FieldValue::Null),
    ]);
    let user = FieldValue::from(consumer_user());
    let new_session = FieldValue::from(FieldMap::from([
        ("user".into(), user.clone()),
        ("session".into(), session.clone().into()),
    ]));
    harness
        .cache
        .insert("new-session", new_session.stringify()?.unwrap().into())?;
    let active = FieldValue::from(vec![FieldValue::from(FieldMap::from([
        ("token".into(), "new-session".into()),
        ("expiresAt".into(), (NOW + 60_000).into()),
    ]))]);
    harness
        .cache
        .insert("active-sessions-owner", active.stringify()?.unwrap().into())?;
    let mut request = AuthRequest::new(HttpMethod::Post, "/sign-in/email");
    let token = sign_value(SECRET, &format!("owner!{identifier}"))?;
    request_cookie(
        &mut request,
        &context,
        TRUST_DEVICE_COOKIE_SUFFIX,
        &format!("{token}!{identifier}"),
    )?;
    context.session_manager().publish_session(
        &request,
        NativeSessionData {
            session: better_auth_core::SessionView::from_field_values(session)?,
            user: user.clone(),
        },
    )?;
    let mut response = AuthResponse::native(None, FieldValue::Undefined);
    let before = harness.state(&inner)?;
    harness.activate();
    let harness = &harness;
    let result = context
        .with_native_context(
            better_auth_core::NativeRequest::default(),
            |context| async move {
                let result = plugin
                    .after_request(&request, &mut response, &context)
                    .await;
                let snapshot = request.new_session()?.unwrap();
                assert!(
                    snapshot.user.strict_equals(&user),
                    "The failure must retain the issued User identity"
                );
                let current = FieldValue::from(FieldMap::from([
                    ("user".into(), snapshot.user),
                    ("session".into(), FieldMap::from(snapshot.session).into()),
                ]));
                let context_headers = request.take_response_headers()?;
                harness.record(
                    "consumer:trust-finally",
                    [
                        ("newSession".into(), harness.observe(&current)?),
                        ("headers".into(), headers(&response.headers)),
                        ("cookies".into(), cookies(&response.headers)),
                        ("contextHeaders".into(), headers(&context_headers)),
                    ],
                );
                result.map(|()| FieldValue::Undefined)
            },
        )
        .await;
    harness.finish(before, harness.outcome(result)?, &inner)
}
