use super::*;

pub(super) struct ResolvedSigningKey {
    algorithm: String,
    key_id: FieldValue,
    signer: Box<dyn JwsSigner>,
}

impl ResolvedSigningKey {
    pub(super) fn sign(
        &self,
        payload: FieldMap,
        options: &JwtSigningOptions,
    ) -> AuthResult<String> {
        let mut header = FieldMap::from_json(options.header.clone())?;
        let _ = header.insert("alg".into(), self.algorithm.clone().into());
        let _ = header.insert("kid".into(), self.key_id.clone());
        jose::sign(payload, header, self.signer.as_ref())
    }
}

impl JwtPlugin {
    pub(super) async fn sign_session<S: AuthSchema>(
        &self,
        session: Option<better_auth_core::session::NativeSessionData>,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<String> {
        let user = || {
            session.as_ref().map(|data| &data.user).ok_or_else(|| {
                AuthError::type_error(
                    "null is not an object (evaluating 'ctx.context.session.user')",
                )
            })
        };
        let mut payload = FieldMap::from([("iat".into(), (Utc::now().timestamp() as f64).into())]);
        match &self.config.define_payload {
            Some(callback) => {
                payload.extend(FieldMap::from_json(
                    callback(serde_json::to_value(&session)?).await?,
                )?);
            }
            None => keys::spread(&mut payload, user()?.clone())?,
        }
        let subject = match &self.config.get_subject {
            Some(callback) => callback(serde_json::to_value(&session)?).await?.into(),
            None => match user()? {
                FieldValue::Null => {
                    return Err(AuthError::type_error(
                        "null is not an object (evaluating 'ctx.context.session.user.id')",
                    ));
                }
                FieldValue::Undefined => {
                    return Err(AuthError::type_error(
                        "Cannot read properties of undefined (reading 'id')",
                    ));
                }
                value => value.model_property("id")?,
            },
        };
        let _ = payload.insert("sub".into(), subject);
        self.sign_fields_in_endpoint(payload, &JwtSigningOptions::default(), endpoint)
            .await
    }

    /// Sign an application payload with the same persisted keys as `/token`.
    pub async fn sign<S: AuthSchema>(
        &self,
        payload: Map<String, Value>,
        ctx: &AuthContext<S>,
    ) -> AuthResult<String> {
        self.sign_with_options(payload, &JwtSigningOptions::default(), ctx)
            .await
    }

    /// Sign a native payload with explicit protected headers and key selection.
    /// Use `sign_in_endpoint` to retain an endpoint request and transaction.
    pub async fn sign_with_options<S: AuthSchema>(
        &self,
        payload: Map<String, Value>,
        options: &JwtSigningOptions,
        ctx: &AuthContext<S>,
    ) -> AuthResult<String> {
        ctx.with_native_context(Default::default(), |resolved| async move {
            let mut endpoint = EndpointContext::new(
                None,
                better_auth_core::FieldValue::from_json(json!({"payload":payload}))?,
                &resolved,
            );
            endpoint.path = Some("virtual:");
            self.sign_in_endpoint(payload, options, &endpoint).await
        })
        .await
    }

    /// Sign with the supplied endpoint context, including its active transaction.
    pub async fn sign_in_endpoint<S: AuthSchema>(
        &self,
        payload: Map<String, Value>,
        options: &JwtSigningOptions,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<String> {
        self.sign_fields_in_endpoint(FieldMap::from_json(payload)?, options, endpoint)
            .await
    }

    async fn sign_fields_in_endpoint<S: AuthSchema>(
        &self,
        fields: FieldMap,
        options: &JwtSigningOptions,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<String> {
        let config = &endpoint.auth.config;
        let defaults = self.default_claims(&fields, config)?;
        if let Some(callback) = &self.config.custom_sign {
            let mut payload = fields.clone();
            for name in ["iat", "exp", "nbf", "iss", "aud"] {
                let value = defaults
                    .get(name)
                    .or_else(|| fields.get(name))
                    .cloned()
                    .unwrap_or_default();
                let _ = payload.insert(name.into(), value);
            }
            return callback(payload.json()?, options.clone()).await;
        }
        let key = self.resolve_local_signing_key(options, endpoint).await?;
        let mut payload = better_auth_core::StructuredCloneContext::new().clone_map(&fields)?;
        claims::prepare_local_claims(&mut payload, &fields, &defaults)?;
        key.sign(payload, options)
    }

    pub(super) async fn resolve_local_signing_key<S: AuthSchema>(
        &self,
        options: &JwtSigningOptions,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<ResolvedSigningKey> {
        let config = &endpoint.auth.config;
        let primary = self.config.primary_algorithm();
        let mut selected = if let Some(id) = &options.key_id {
            let key = self.read_key(id, endpoint).await?;
            if !key.is_truthy() {
                return Err(AuthError::better_auth(format!(
                    "signJWT: signingKeyId \"{id}\" not found in JWKS. The key must be provisioned before it can be referenced."
                )));
            }
            if let Some(expected) = options.algorithm {
                let alg = keys::algorithm(&key, primary.name().into())?;
                if !alg.strict_equals(&expected.name().into()) {
                    let actual = keys::algorithm(
                        &key,
                        format!("unset (inherits keyPairConfig.alg \"{}\")", primary.name()).into(),
                    )?;
                    let mut message = format!("signJWT: signingKeyId \"{id}\" has alg \"")
                        .encode_utf16()
                        .collect::<Vec<_>>();
                    message.extend_from_slice(actual.display_utf16()?.as_utf16());
                    message.extend(
                        format!(
                            "\" but signingAlgorithm was set to \"{}\".",
                            expected.name()
                        )
                        .encode_utf16(),
                    );
                    return Err(AuthError::better_auth_native(
                        better_auth_core::Utf16String::from_units(message),
                    ));
                }
            }
            key
        } else {
            let preferred = self
                .read_latest_key(Some(options.algorithm.unwrap_or(primary).name()), endpoint)
                .await?;
            if !(preferred.is_null() || preferred.is_undefined()) || options.algorithm.is_some() {
                preferred
            } else {
                self.read_latest_key(None, endpoint).await?
            }
        };
        if !selected.is_truthy()
            && let Some(algorithm) = options.algorithm
        {
            let parameters = self
                .config
                .key_pair_configs
                .iter()
                .find(|config| config.algorithm == algorithm)
                .copied()
                .or_else(|| {
                    (algorithm == primary).then_some(JwtKeyPairConfig {
                        algorithm,
                        modulus_length: self.config.modulus_length,
                    })
                })
                .ok_or_else(|| {
                    let advertised = self
                        .config
                        .key_pair_configs
                        .iter()
                        .map(|config| config.algorithm.name())
                        .collect::<Vec<_>>()
                        .join(", ");
                    let advertised = if advertised.is_empty() { "none" } else { &advertised };
                    AuthError::better_auth(format!(
                        "signJWT: no key with alg \"{}\" found in JWKS. The plugin auto-mints only one key matching keyPairConfig.alg=\"{}\"; additional algs configured via keyPairConfigs: {advertised}. Add \"{}\" to jwks.keyPairConfigs so the plugin provisions it on first use, or mint the key explicitly via createJwk().",
                        algorithm.name(), primary.name(), algorithm.name()
                    ))
                })?;
            selected = self.create_key_pair_value(parameters, endpoint).await?;
        }
        let key = if !selected.is_truthy() || keys::expires_before(&selected)? {
            if options.key_id.is_some() || options.algorithm.is_some() {
                return Err(AuthError::better_auth(
                    "signJWT: requested signing key is expired and an explicit kid/alg was provided; not auto-minting a replacement. Rotate the key explicitly.",
                ));
            }
            self.create_key(endpoint).await?
        } else {
            selected
        };
        let private = if self.config.disable_private_key_encryption {
            key.model_property("privateKey")?
        } else {
            let ciphertext = keys::parse_json(&key.model_property("privateKey")?)?;
            crate::plugins::symmetric::decrypt_field(
                config.encryption_secret(),
                &ciphertext,
            ).map_err(|_| AuthError::better_auth("Failed to decrypt private key. Make sure the secret currently in use is the same as the one used to encrypt the private key. If you are using a different secret, either clean up your JWKS or disable private key encryption."))?.into()
        };
        let algorithm = keys::algorithm(&key, primary.name().into())?;
        let (algorithm, private) = keys::import(keys::parse_json(&private)?, &algorithm)?;
        let signer: Box<dyn JwsSigner> = match algorithm.as_str() {
            "EdDSA" => Box::new(jws::EdDSA.signer_from_jwk(&private).map_err(jose_error)?),
            "RS256" => Box::new(jws::RS256.signer_from_jwk(&private).map_err(jose_error)?),
            "ES256" => Box::new(jws::ES256.signer_from_jwk(&private).map_err(jose_error)?),
            "ES512" => Box::new(jws::ES512.signer_from_jwk(&private).map_err(jose_error)?),
            "PS256" => Box::new(jws::PS256.signer_from_jwk(&private).map_err(jose_error)?),
            _ => {
                return Err(AuthError::config(format!(
                    "Unsupported JWT signing algorithm: {algorithm}"
                )));
            }
        };
        Ok(ResolvedSigningKey {
            algorithm,
            key_id: key.model_property("id")?,
            signer,
        })
    }

    fn default_claims(
        &self,
        payload: &FieldMap,
        config: &better_auth_core::AuthConfig,
    ) -> AuthResult<FieldMap> {
        let expiration =
            claims::default_expiration(&self.config.expiration_time, payload.get("iat"))?;
        let mut defaults = FieldMap::new();
        for (claim, default) in [
            ("exp", expiration),
            (
                "iss",
                self.config
                    .issuer
                    .as_deref()
                    .unwrap_or_else(|| config.base_url.as_static().unwrap_or(""))
                    .into(),
            ),
            (
                "aud",
                match &self.config.audience {
                    Some(audience) => FieldValue::from_json(serde_json::to_value(audience)?)?,
                    None => config.base_url.as_static().unwrap_or("").into(),
                },
            ),
        ] {
            let value = payload
                .get(claim)
                .filter(|value| !value.is_null() && !value.is_undefined())
                .cloned()
                .unwrap_or(default);
            let _ = defaults.insert(claim.to_owned(), value);
        }
        Ok(defaults)
    }
}

#[cfg(test)]
#[path = "native_keyring_tests.rs"]
mod native_tests;
