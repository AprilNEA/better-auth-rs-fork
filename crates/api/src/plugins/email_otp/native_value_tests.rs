#![expect(
    clippy::panic_in_result_fn,
    reason = "Native OTP tests assert byte conversion, mutation order, and plaintext identity."
)]

use super::*;
use better_auth_core::{FieldFunction, FieldMap, Utf16String};

#[test]
fn comparison_converts_byte_values_and_preserves_iterator_collection_order() -> AuthResult<()> {
    assert_eq!(
        comparison_bytes(&vec![(-207.5).into(), 306.into(), 51.9.into(), f64::NAN.into()].into())?,
        [49, 50, 51, 0]
    );
    assert_eq!(
        comparison_bytes(&Utf16String::from_units(vec![0xd800]).into())?,
        "�".as_bytes()
    );

    for array in [true, false] {
        let input: FieldValue = if array {
            vec![FieldValue::Undefined, 50.into()].into()
        } else {
            FieldMap::from([
                ("0".into(), FieldValue::Undefined),
                ("1".into(), 50.into()),
                ("length".into(), 2.into()),
            ])
            .into()
        };
        let mutated = input.clone();
        let first: FieldValue = FieldMap::from([(
            "valueOf".into(),
            FieldFunction::contextual(move |_, _| {
                mutated.set_model_property("1", 255.into())?;
                Ok(49.into())
            })
            .into(),
        )])
        .into();
        input.set_model_property("0", first)?;
        let actual = comparison_bytes(&input)?;
        input.set_model_property("0", FieldValue::Null)?;
        assert_eq!(actual, [49, if array { 50 } else { 255 }]);
        assert_eq!(input.model_property("1")?, 255.into());
    }
    Ok(())
}

#[tokio::test]
async fn plain_otp_recovery_retains_identity_and_compares_native_byte_inputs() -> AuthResult<()> {
    let plugin = EmailOtpPlugin::new();
    let secret = better_auth_core::SecretKey::Single("otp-comparison-test-secret");
    let bytes: FieldValue = vec![49.into(), 50.into(), 51.into()].into();
    assert!(plugin.recover(&bytes, secret).await?.strict_equals(&bytes));
    assert!(plugin.matches(&bytes, "123", secret).await?);
    assert!(!plugin.matches(&bytes, "124", secret).await?);
    let array_like: FieldValue = FieldMap::from([
        ("0".into(), "49".into()),
        ("1".into(), "50".into()),
        ("2".into(), "51".into()),
        ("length".into(), 3.into()),
    ])
    .into();
    assert!(plugin.matches(&array_like, "123", secret).await?);
    Ok(())
}
