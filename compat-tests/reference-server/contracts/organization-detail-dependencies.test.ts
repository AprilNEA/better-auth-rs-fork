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
