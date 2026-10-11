import { expect, test } from "bun:test";
import type { DBFieldAttribute } from "@better-auth/core/db";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { organization } from "better-auth/plugins";

const { getOrgAdapter } = await import(new URL("../node_modules/better-auth/dist/plugins/organization/adapter.mjs", import.meta.url).href);
type Fields = Record<string, unknown>;
const date = () => new Date("2030-01-01T00:00:00.000Z");

for (const joins of [false, true]) for (const mapped of [false, true]) for (const reject of [false, true]) {
  test(`Memory full Organization uses preceding relation outputs: joins=${joins}, mapped=${mapped}, reject=${reject}`, async () => {
    const events: unknown[][] = [];
    const failure = new TypeError("detail-dependency-output-rejected");
    const trace = (name: string): DBFieldAttribute => ({ type: "string", transform: { output(value) {
      events.push([name, structuredClone(value)]);
      if (reject && name === "invitation.role") throw failure;
      return value;
    } } });
    const parent: Fields = {
      id: "organization", name: "Organization", slug: "organization", logo: null, metadata: null, createdAt: date(),
    };
    const invitation: Fields = {
      id: "invitation", organizationId: "organization", email: "owner@detail-dependencies.test", role: "member",
      teamId: null, status: "pending", inviterId: "owner", createdAt: date(), expiresAt: date(),
    };
    const member: Fields = {
      id: "member", organizationId: "stale-member-key", userId: "owner", role: "member", createdAt: date(),
    };
    const team: Fields = {
      id: "team", organizationId: "stale-team-key", name: "Team", memberCount: 0, createdAt: date(), updatedAt: null,
    };
    const user = {
      id: "owner", name: "Owner", email: "owner@detail-dependencies.test", emailVerified: true,
      image: null, createdAt: date(), updatedAt: date(),
    };
    const memory: Record<string, Fields[]> = {
      user: [user], session: [], account: [], verification: [], teamMember: [],
      organization: [{ ...parent,
        [mapped ? "stored_invitation" : "invitation"]: "stale-member-key",
        [mapped ? "stored_member" : "member"]: "stale-team-key",
      }],
      invitation: [invitation], member: [member], team: [team],
    };
    const before = structuredClone(memory);
    const organizationOptions = { teams: { enabled: true } };
    const context = await betterAuth({
      database: memoryAdapter(memory), baseURL: "http://detail-dependencies.test",
      secret: "detail-dependency-contract-at-least-thirty-two-characters",
      logger: { disabled: true }, telemetry: { enabled: false }, advanced: { database: { joins } },
      user: { additionalFields: { name: trace("user.name") } },
      plugins: [organization(organizationOptions), { id: "detail-dependency-fields", schema: {
        organization: { fields: {
          invitation: { ...trace("organization.invitation"), ...(mapped ? { fieldName: "stored_invitation" } : {}) },
          member: { ...trace("organization.member"), ...(mapped ? { fieldName: "stored_member" } : {}) },
        } },
        invitation: { fields: { role: trace("invitation.role") } },
        member: { fields: {
          organizationId: { type: "string", references: { model: "organization", field: "invitation" } },
          role: trace("member.role"),
        } },
        team: { fields: {
          organizationId: { type: "string", references: { model: "organization", field: "member" } },
          name: trace("team.name"),
        } },
      } }],
    }).$context;
    const operation = getOrgAdapter(context, organizationOptions).findFullOrganization({
      organizationId: "organization", includeTeams: true,
    });
    if (reject) await expect(operation).rejects.toBe(failure);
    else expect(await operation).toStrictEqual({
      ...parent,
      invitations: [invitation],
      members: joins ? [{ ...member, user: { id: user.id, name: user.name, email: user.email, image: user.image } }] : [],
      teams: joins ? [team] : [],
    });
    expect(events).toStrictEqual([
      ["organization.invitation", joins && !mapped ? [invitation] : "stale-member-key"],
      ["organization.member", joins && !mapped ? [member] : "stale-team-key"],
      ["invitation.role", "member"],
      ...(!reject && joins ? [["member.role", "member"], ["team.name", "Team"], ["user.name", "Owner"]] : []),
    ]);
    expect(memory).toStrictEqual(before);
  });
}

for (const joins of [false, true]) {
  for (const failure of ["member-before-owner", "organization-before-invitation", "invitation-before-team", "unconfigured-summary"] as const) {
    test(`Memory full Organization public value order: joins=${joins}, ${failure}`, async () => {
      const events: unknown[][] = [];
      const callable = () => "native-summary";
      const image = date();
      const parent = { id: "organization", name: "Organization", slug: "organization", logo: null, metadata: null, createdAt: date() };
      const invitation = { id: "invitation", organizationId: "organization", email: "owner@detail-dependencies.test",
        role: "member", teamId: null, status: "pending", inviterId: "owner", createdAt: date(), expiresAt: date() };
      const member = { id: "member", organizationId: "organization", userId: "owner", role: "member", createdAt: date() };
      const team = { id: "team", organizationId: "organization", name: "Team", memberCount: 0, createdAt: date(), updatedAt: null };
      const user = { id: "owner", name: "Owner", email: "owner@detail-dependencies.test", emailVerified: true,
        image: null, createdAt: date(), updatedAt: date() };
      const memory = { user: [user], session: [], account: [], verification: [], teamMember: [], organization: [parent],
        invitation: [invitation], member: failure === "member-before-owner"
          ? [member, { ...member, id: "missing-owner-member", userId: "missing-owner" }] : [member], team: [team] };
      const before = structuredClone(memory);
      const field = (label: string, replacement?: unknown): DBFieldAttribute => ({ type: "string", transform: { output(value) {
        events.push([label, structuredClone(value)]);
        return replacement === undefined ? value : replacement;
      } } });
      const declaration: Record<string, { fields: Record<string, DBFieldAttribute> }> = {
        organization: { fields: { name: field("organization.name", failure === "organization-before-invitation" ? callable : undefined) } },
        invitation: { fields: { role: field("invitation.role", failure === "invitation-before-team" ? callable : undefined) } },
        member: { fields: { role: field("member.role", failure === "member-before-owner" ? callable : undefined) } },
        team: { fields: { name: field("team.name") } },
      };
      const singular = failure === "organization-before-invitation" ? "invitation"
        : failure === "invitation-before-team" ? "team" : undefined;
      if (singular) declaration[singular].fields.organizationId = {
        type: "string", references: { model: "organization", field: "id" }, unique: true,
      };
      const configured = failure === "member-before-owner" ? "member" : failure === "organization-before-invitation" ? "organization"
        : failure === "invitation-before-team" ? "invitation" : undefined;
      const options = { teams: { enabled: true }, ...(configured ? { schema: {
        [configured]: { additionalFields: { [configured === "organization" ? "name" : "role"]: { type: "string" as const, returned: false } } },
      } } : {}) };
      const context = await betterAuth({
        database: memoryAdapter(memory), baseURL: "http://detail-dependencies.test",
        secret: "detail-dependency-contract-at-least-thirty-two-characters",
        logger: { disabled: true }, telemetry: { enabled: false }, advanced: { database: { joins } },
        user: { additionalFields: {
          name: field("user.name", failure === "unconfigured-summary" ? callable : undefined),
          image: field("user.image", failure === "unconfigured-summary" ? image : undefined),
        } },
        plugins: [organization(options), { id: "full-public-values", schema: declaration }],
      }).$context;
      const operation = getOrgAdapter(context, options).findFullOrganization({
        organizationId: "organization", includeTeams: failure !== "unconfigured-summary",
      });
      if (failure === "unconfigured-summary") {
        const result = await operation;
        expect(result).toStrictEqual({ ...parent, invitations: [invitation],
          members: [{ ...member, user: { id: "owner", name: callable, email: user.email, image } }], teams: undefined });
        expect(Object.hasOwn(result, "teams")).toBe(true);
        expect(result.members[0].user.name).toBe(callable);
        expect(result.members[0].user.image).toBe(image);
      } else {
        let expected: unknown;
        try { structuredClone({ callable }); } catch (error) { expected = error; }
        let actual: unknown;
        try { await operation; } catch (error) { actual = error; }
        expect(actual).toBeInstanceOf(DOMException);
        expect({ name: (actual as Error).name, message: (actual as Error).message, keys: Object.keys(actual as object) })
          .toStrictEqual({ name: (expected as Error).name, message: (expected as Error).message, keys: Object.keys(expected as object) });
      }
      expect(events).toStrictEqual([
        ["organization.name", "Organization"], ["invitation.role", "member"], ["member.role", "member"],
        ...(failure === "member-before-owner" ? [["member.role", "member"]] : []),
        ...(failure !== "unconfigured-summary" ? [["team.name", "Team"]] : []),
        ["user.name", "Owner"], ["user.image", null],
      ]);
      expect(memory).toStrictEqual(before);
    });
  }
}
