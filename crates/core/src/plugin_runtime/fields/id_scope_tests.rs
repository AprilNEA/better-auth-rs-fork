#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify shared ID history across reentrant callbacks and suspended conversion failures"
)]

use super::*;
use crate::user_fields::{UserFieldTransform, await_adapter_boundary};

#[tokio::test]
async fn id_input_sync_callback_keeps_reentrant_output_policy() -> AuthResult<()> {
    let fields = ModelFields::default();
    let role = EntityRole::Session;
    fields.begin_id_query(role)?;
    let callback_fields = fields.clone();
    let callback = UserFieldTransform::new(move |value| {
        assert!(
            callback_fields
                .id_input_policy(role)?
                .is_some_and(|policy| policy.force_allow_id && policy.supports_native_uuid)
        );
        callback_fields.begin_id_output(role)?;
        Ok(value)
    });
    let output = fields
        .with_id_input(
            role,
            AdapterIdInput {
                force_allow_id: true,
                supports_native_uuid: true,
            },
            async { callback.call_sync("retained".into()) },
        )
        .await?;
    assert_eq!(output, Value::from("retained"));
    assert!(fields.id_input_policy(role)?.is_none());
    Ok(())
}

#[tokio::test]
async fn id_input_resume_keeps_peer_output_policy_and_original_error() -> AuthResult<()> {
    let fields = ModelFields::default();
    let role = EntityRole::Session;
    let original: Value = FieldMap::from([("cause".into(), "conversion failed".into())]).into();
    let input = fields.with_id_input(
        role,
        AdapterIdInput {
            force_allow_id: true,
            supports_native_uuid: true,
        },
        async {
            assert!(
                fields
                    .id_input_policy(role)?
                    .is_some_and(|policy| policy.force_allow_id && policy.supports_native_uuid)
            );
            await_adapter_boundary().await;
            assert!(fields.id_input_policy(role)?.is_none());
            Err::<(), _>(AuthError::from_thrown(original.clone()))
        },
    );
    assert!(fields.id_input_policy(role)?.is_none());
    let output = async {
        assert!(
            fields
                .id_input_policy(role)?
                .is_some_and(|policy| policy.force_allow_id && policy.supports_native_uuid)
        );
        fields.id_output_initializer(role)()
    };
    let (input, output) = tokio::join!(biased; input, output);
    output?;
    let error = input
        .err()
        .ok_or_else(|| AuthError::internal("Suspended conversion unexpectedly succeeded"))?;
    assert!(
        error
            .raw_value()
            .is_some_and(|cause| cause.strict_equals(&original))
    );
    assert!(fields.id_input_policy(role)?.is_none());
    Ok(())
}
