//! State stores active array bindings; captured tables and rows retain their own identities.

use super::operation::{MemoryGate, MemoryOperation};
use super::rows::RowRef;
use super::table::TableRef;
use super::*;
use crate::store::schema::EntityRole;

/// Clone captures bindings. Use shallow_snapshot to copy the independent row lists.
#[derive(Clone)]
pub(super) struct State {
    pub(super) organizations: TableRef<FieldMap>,
    pub(super) members: TableRef<FieldMap>,
    pub(super) invitations: TableRef<FieldMap>,
    pub(super) teams: TableRef<FieldMap>,
    pub(super) team_members: TableRef<FieldMap>,
    pub(super) organization_roles: TableRef<FieldMap>,
    pub(super) jwks: TableRef<FieldMap>,
    pub(super) users: TableRef<UserView>,
    pub(super) wallets: TableRef<FieldMap>,
    pub(super) sessions: TableRef<FieldMap>,
    pub(super) accounts: TableRef<FieldMap>,
    pub(super) verifications: TableRef<FieldMap>,
    pub(super) two_factors: TableRef<FieldMap>,
    pub(super) device_codes: TableRef<FieldMap>,
    pub(super) api_keys: TableRef<FieldMap>,
    pub(super) passkeys: TableRef<FieldMap>,
    pub(super) rate_limits: TableRef<FieldMap>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Arc::default())
    }
}

impl State {
    pub(super) fn new(gate: MemoryGate) -> Self {
        Self {
            organizations: TableRef::new(gate.clone()),
            members: TableRef::new(gate.clone()),
            invitations: TableRef::new(gate.clone()),
            teams: TableRef::new(gate.clone()),
            team_members: TableRef::new(gate.clone()),
            organization_roles: TableRef::new(gate.clone()),
            jwks: TableRef::new(gate.clone()),
            users: TableRef::new(gate.clone()),
            wallets: TableRef::new(gate.clone()),
            sessions: TableRef::new(gate.clone()),
            accounts: TableRef::new(gate.clone()),
            verifications: TableRef::new(gate.clone()),
            two_factors: TableRef::new(gate.clone()),
            device_codes: TableRef::new(gate.clone()),
            api_keys: TableRef::new(gate.clone()),
            passkeys: TableRef::new(gate.clone()),
            rate_limits: TableRef::new(gate),
        }
    }

    pub(super) fn table(&self, role: EntityRole) -> AuthResult<&TableRef<FieldMap>> {
        match role {
            EntityRole::Organization => Ok(&self.organizations),
            EntityRole::Member => Ok(&self.members),
            EntityRole::Invitation => Ok(&self.invitations),
            EntityRole::Team => Ok(&self.teams),
            EntityRole::TeamMember => Ok(&self.team_members),
            EntityRole::OrganizationRole => Ok(&self.organization_roles),
            EntityRole::Jwk => Ok(&self.jwks),
            EntityRole::WalletAddress => Ok(&self.wallets),
            EntityRole::Session => Ok(&self.sessions),
            EntityRole::Account => Ok(&self.accounts),
            EntityRole::Verification => Ok(&self.verifications),
            EntityRole::TwoFactor => Ok(&self.two_factors),
            EntityRole::DeviceCode => Ok(&self.device_codes),
            EntityRole::ApiKey => Ok(&self.api_keys),
            EntityRole::Passkey => Ok(&self.passkeys),
            EntityRole::RateLimit => Ok(&self.rate_limits),
            EntityRole::User => Err(AuthError::internal("User storage requires its typed table")),
        }
    }

    pub(super) fn table_mut(&mut self, role: EntityRole) -> AuthResult<&mut TableRef<FieldMap>> {
        match role {
            EntityRole::Organization => Ok(&mut self.organizations),
            EntityRole::Member => Ok(&mut self.members),
            EntityRole::Invitation => Ok(&mut self.invitations),
            EntityRole::Team => Ok(&mut self.teams),
            EntityRole::TeamMember => Ok(&mut self.team_members),
            EntityRole::OrganizationRole => Ok(&mut self.organization_roles),
            EntityRole::Jwk => Ok(&mut self.jwks),
            EntityRole::WalletAddress => Ok(&mut self.wallets),
            EntityRole::Session => Ok(&mut self.sessions),
            EntityRole::Account => Ok(&mut self.accounts),
            EntityRole::Verification => Ok(&mut self.verifications),
            EntityRole::TwoFactor => Ok(&mut self.two_factors),
            EntityRole::DeviceCode => Ok(&mut self.device_codes),
            EntityRole::ApiKey => Ok(&mut self.api_keys),
            EntityRole::Passkey => Ok(&mut self.passkeys),
            EntityRole::RateLimit => Ok(&mut self.rate_limits),
            EntityRole::User => Err(AuthError::internal("User storage requires its typed table")),
        }
    }

    pub(super) fn shallow_snapshot(&self) -> AuthResult<Self> {
        Ok(Self {
            organizations: self.organizations.shallow_copy()?,
            members: self.members.shallow_copy()?,
            invitations: self.invitations.shallow_copy()?,
            teams: self.teams.shallow_copy()?,
            team_members: self.team_members.shallow_copy()?,
            organization_roles: self.organization_roles.shallow_copy()?,
            jwks: self.jwks.shallow_copy()?,
            users: self.users.shallow_copy()?,
            wallets: self.wallets.shallow_copy()?,
            sessions: self.sessions.shallow_copy()?,
            accounts: self.accounts.shallow_copy()?,
            verifications: self.verifications.shallow_copy()?,
            two_factors: self.two_factors.shallow_copy()?,
            device_codes: self.device_codes.shallow_copy()?,
            api_keys: self.api_keys.shallow_copy()?,
            passkeys: self.passkeys.shallow_copy()?,
            rate_limits: self.rate_limits.shallow_copy()?,
        })
    }

    pub(super) fn structured_clone_from(
        operation: &MemoryOperation<'_>,
        mut device_origin: impl FnMut(RowRef<FieldMap>, RowRef<FieldMap>, FieldMap),
    ) -> AuthResult<Self> {
        let mut context = crate::StructuredCloneContext::new();
        Ok(Self {
            organizations: operation
                .capture_table(EntityRole::Organization)?
                .deep_clone(&mut context)?,
            members: operation
                .capture_table(EntityRole::Member)?
                .deep_clone(&mut context)?,
            invitations: operation
                .capture_table(EntityRole::Invitation)?
                .deep_clone(&mut context)?,
            teams: operation
                .capture_table(EntityRole::Team)?
                .deep_clone(&mut context)?,
            organization_roles: operation
                .capture_table(EntityRole::OrganizationRole)?
                .deep_clone(&mut context)?,
            users: operation.capture_users()?.deep_clone(&mut context)?,
            two_factors: operation
                .capture_table(EntityRole::TwoFactor)?
                .deep_clone(&mut context)?,
            device_codes: operation
                .capture_table(EntityRole::DeviceCode)?
                .deep_clone_with(&mut context, &mut device_origin)?,
            api_keys: operation
                .capture_table(EntityRole::ApiKey)?
                .deep_clone(&mut context)?,
            passkeys: operation
                .capture_table(EntityRole::Passkey)?
                .deep_clone(&mut context)?,
            team_members: operation
                .capture_table(EntityRole::TeamMember)?
                .deep_clone(&mut context)?,
            jwks: operation
                .capture_table(EntityRole::Jwk)?
                .deep_clone(&mut context)?,
            wallets: operation
                .capture_table(EntityRole::WalletAddress)?
                .deep_clone(&mut context)?,
            sessions: operation
                .capture_table(EntityRole::Session)?
                .deep_clone(&mut context)?,
            accounts: operation
                .capture_table(EntityRole::Account)?
                .deep_clone(&mut context)?,
            verifications: operation
                .capture_table(EntityRole::Verification)?
                .deep_clone(&mut context)?,
            rate_limits: operation
                .capture_table(EntityRole::RateLimit)?
                .deep_clone(&mut context)?,
        })
    }
}
