# SQLx PostgreSQL source patch

This package contains the published `sqlx-postgres` 0.8.6 source from SQLx commit `bab1b022bd56a64f9a08b46b36b97c5cff19d77e`. The crates.io archive SHA-256 is `db58fcd5a53cf07c184b154801ff91347e4c30d17a3562a635ff028ad5deda46`. The original MIT and Apache licenses are included.

Only `src/error.rs` and `src/message/response.rs` contain production changes. `PgDatabaseError::field` exposes original ErrorResponse fields. `response_length` exposes the original protocol length, including unknown fields. Both methods reuse the retained response body and preserve the driver error source. Packaging also removes trailing whitespace from existing comments, SQL/JSON examples, and numeric-range documentation. A decoder regression covers localized severity, independent positions, original line text, and unknown fields.

All four application dependency roots must use the same patch. The dependency preparation workflow verifies versions and sources and runs the driver regression outside the application workspace. Remove this patch when an upstream SQLx release provides these capabilities and the strict PostgreSQL error contracts pass against that release.

This patch does not change parameter encoding, prepared statements, connection ownership, or transaction behavior.
