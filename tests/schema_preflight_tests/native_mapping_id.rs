use super::*;

#[tokio::test]
async fn explicit_id_alias_and_physical_primary_key_are_independent_schema_requirements() {
    for (primary_key, alias, missing) in [
        (true, false, Some("physical_label")),
        (true, true, None),
        (false, true, Some("person_pk")),
    ] {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        migrator::run_migrations(&database).await.unwrap();
        let mut columns = vec![
            "name BLOB",
            "mail_address BLOB",
            "email_verified BLOB",
            "image BLOB",
            "created_at BLOB",
            "updated_at BLOB",
            "unconfigured TEXT NOT NULL DEFAULT 'legacy-default'",
        ];
        if primary_key {
            columns.push("person_pk TEXT PRIMARY KEY");
        }
        if alias {
            columns.push("physical_label BLOB");
        }
        execute(
            &database,
            &format!("CREATE TABLE physical_people ({})", columns.join(",")),
        )
        .await;
        let before = sqlite::snapshot(&database).await;
        let schema = sqlite::catalog(&database).await;
        let events = Events::default();
        let mut settings = settings();
        settings.user = declaration("id", "storedLabel", &events);
        let store = SeaOrmStore::<Mapped>::new(settings.clone(), database.clone());
        let auth = AuthBuilder::new(settings)
            .store(store)
            .build()
            .await
            .unwrap();
        let result = auth
            .handle_request(AuthRequest::new(HttpMethod::Get, "/api/auth/ok"))
            .await;
        match missing {
            Some(column) => assert_mismatch(
                &mismatch(result.unwrap_err()),
                SchemaFinding::MissingColumn {
                    table: "physical_people".into(),
                    column: column.into(),
                },
                format!(
                    "Database schema mismatch\n\n  Missing columns\n    physical_people.{column}\n\n  help: Run `npx auth migrate` to add the missing tables and columns."
                ),
            ),
            None => {
                let response = result.unwrap();
                assert_eq!(response.status, 200);
                assert_eq!(
                    serde_json::from_slice::<Value>(response.body.bytes().unwrap().as_ref())
                        .unwrap(),
                    json!({"ok":true})
                );
            }
        }
        assert!(events.lock().unwrap().is_empty());
        assert_eq!(sqlite::snapshot(&database).await, before);
        assert_eq!(sqlite::catalog(&database).await, schema);
    }
}
