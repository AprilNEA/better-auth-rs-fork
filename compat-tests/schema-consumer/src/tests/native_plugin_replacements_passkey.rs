include!("native_plugin_replacements.rs");

target!(
    counter_string,
    "BETTER_AUTH_NATIVE_REPLACEMENT_PASSKEY_COUNTER_STRING_SCHEMA",
    "passkey-counter-string",
    Passkey
);
target!(
    backup_boolean,
    "BETTER_AUTH_NATIVE_REPLACEMENT_PASSKEY_BACKUP_BOOLEAN_SCHEMA",
    "passkey-backup-boolean",
    Passkey
);
