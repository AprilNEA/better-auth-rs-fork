use better_auth::{AuthError, plugins::SiwePlugin};

pub(crate) fn wallet_plugin() -> SiwePlugin {
    SiwePlugin::new(
        "wallet-fields.test",
        || async {
            Err(AuthError::internal(
                "The display-field contract must not request a nonce",
            ))
        },
        |_| async {
            Err(AuthError::internal(
                "The display-field contract must not verify a message",
            ))
        },
    )
}
