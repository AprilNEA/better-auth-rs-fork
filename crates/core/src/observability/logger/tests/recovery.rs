use super::*;

struct ThrowingSink(FieldValue);

impl LogSink for ThrowingSink {
    fn log(&self, _: LogLevel, _: LogArgument<'_>, _: &[LogArgument<'_>]) -> AuthResult<()> {
        Err(AuthError::from_thrown(self.0.clone()))
    }
}

struct FailedInitialization {
    original: LoggerOptions,
    replacement: Option<LoggerSource>,
    failure: FieldValue,
}

#[async_trait::async_trait]
impl crate::AuthPlugin<crate::store::StatelessSchema> for FailedInitialization {
    fn name(&self) -> &'static str {
        "logger-failed-initialization"
    }

    fn routes(&self) -> Vec<crate::AuthRoute> {
        Vec::new()
    }

    async fn on_request(
        &self,
        _: &crate::AuthRequest,
        _: &crate::AuthContext<crate::store::StatelessSchema>,
    ) -> AuthResult<Option<crate::AuthResponse>> {
        Ok(None)
    }

    async fn on_init(
        &self,
        context: &mut crate::AuthInitContext<crate::store::StatelessSchema>,
    ) -> AuthResult<()> {
        if let Some(replacement) = &self.replacement {
            context.config = Arc::new(crate::AuthConfig {
                logger: replacement.clone(),
                ..Default::default()
            });
            return Err(AuthError::from_thrown(self.failure.clone()));
        }
        self.original
            .set_log(Some(Arc::new(ThrowingSink(self.failure.clone()))));
        context
            .logger()
            .error("throwing during initialization", &[])
    }
}

#[tokio::test]
async fn failed_initialization_retains_the_original_live_owner_and_error_identity() -> AuthResult<()>
{
    for replace_options in [false, true] {
        let first = Arc::new(Capture::default());
        let recovered = Arc::new(Capture::default());
        let replacement = Arc::new(Capture::default());
        let options = LoggerOptions::new(LoggerConfig {
            log: Some(first.clone()),
            ..Default::default()
        });
        let config = crate::AuthConfig {
            logger: options.clone().into(),
            ..Default::default()
        };
        let database = Arc::new(crate::store::EphemeralStore::default());
        let mut context = crate::AuthInitContext::new(Arc::new(config), database)?;
        context.logger().error("before", &[])?;
        let failure: FieldValue = crate::FieldMap::new().into();
        let error = context
            .initialize_plugin(&FailedInitialization {
                original: options.clone(),
                replacement: replace_options.then(|| {
                    LoggerConfig {
                        log: Some(replacement.clone()),
                        ..Default::default()
                    }
                    .into()
                }),
                failure: failure.clone(),
            })
            .await
            .expect_err("initialization fails");
        assert!(
            error
                .raw_value()
                .expect("native error remains")
                .strict_equals(&failure)
        );
        options.set_log(Some(recovered.clone()));
        context.logger().error("after failure", &[])?;
        context.config.logger()?.error("restored cache", &[])?;
        assert_eq!(
            first.0.lock().expect("first sink is readable").as_slice(),
            [(LogLevel::Error, "before".into(), Vec::new()),]
        );
        assert_eq!(
            recovered
                .0
                .lock()
                .expect("recovered sink is readable")
                .as_slice(),
            [
                (LogLevel::Error, "after failure".into(), Vec::new()),
                (LogLevel::Error, "restored cache".into(), Vec::new()),
            ]
        );
        assert!(
            replacement
                .0
                .lock()
                .expect("replacement sink is readable")
                .is_empty()
        );
    }
    Ok(())
}

#[test]
fn every_convenience_method_propagates_a_sink_failure() -> AuthResult<()> {
    let failure: FieldValue = crate::FieldMap::new().into();
    let logger = Logger::new(LoggerConfig {
        level: Some(LogLevel::Debug),
        log: Some(Arc::new(ThrowingSink(failure.clone()))),
        ..Default::default()
    })?;
    for result in [
        logger.debug("failure", &[]),
        logger.info("failure", &[]),
        logger.success("failure", &[]),
        logger.warn("failure", &[]),
        logger.error("failure", &[]),
    ] {
        assert!(
            result
                .expect_err("sink fails")
                .raw_value()
                .expect("native failure retained")
                .strict_equals(&failure)
        );
    }
    Ok(())
}
