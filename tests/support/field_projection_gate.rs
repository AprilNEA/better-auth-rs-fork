use better_auth_core::{AuthError, AuthResult, FieldValue, user_fields::UserFieldTransform};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

#[derive(Debug)]
pub(super) struct Call {
    pub(super) name: &'static str,
    pub(super) value: FieldValue,
    pub(super) reply: oneshot::Sender<AuthResult<FieldValue>>,
}

pub(super) fn callback<T: Send + 'static>(
    sender: &mpsc::UnboundedSender<T>,
    name: &'static str,
    event: impl Fn(Call) -> T + Send + Sync + 'static,
) -> UserFieldTransform {
    let sender = sender.clone();
    let event = Arc::new(event);
    UserFieldTransform::new_async(move |value| {
        let (sender, event) = (sender.clone(), event.clone());
        async move {
            let (reply, result) = oneshot::channel();
            sender
                .send(event(Call { name, value, reply }))
                .map_err(|_| AuthError::internal("Field controller closed"))?;
            result
                .await
                .map_err(|_| AuthError::internal("Field answer missing"))?
        }
    })
}
