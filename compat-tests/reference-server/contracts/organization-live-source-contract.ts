import { betterAuth, type BetterAuthOptions } from "better-auth";
import { organization } from "better-auth/plugins";
import { setup } from "./organization-invitation-response-contract";
import { date, type Backend, type Fields, type Policies } from "./organization-team-member-contract";

export type Model = "organization" | "invitation" | "team" | "organizationRole";
export const models: Model[] = ["organization", "invitation", "team", "organizationRole"];
export const whereId = (value: string) => [{ field: "id", value }];
export const past = () => new Date("2020-01-01T00:00:00.000Z");
export const early = (model: Model) => model === "organization" || model === "team" ? "name" : "organizationId";
export const late = (model: Model) => ({ organization: "metadata", invitation: "expiresAt", team: "organizationId", organizationRole: "permission" })[model];
export const changed = (model: Model) => model === "invitation" ? past() : model === "team" ? "other" : '{"changed":true}';
export const updated = (model: Model, row: Fields) => ({ ...row, ...updateData(model) });
const updateData = (model: Model) => model === "invitation" ? { status: "accepted" } : model === "organizationRole" ? { role: "Updated" } : { name: "Updated" };

export function visible(model: Model, id: string, label: string): Fields {
  switch (model) {
    case "organization": return { name: label, slug: `slug-${label}`, logo: null, createdAt: date(0), metadata: "{}", id };
    case "invitation": return { organizationId: "source-parent", email: `${label}@fields.test`, role: "member", teamId: null, status: "pending", expiresAt: date(0), createdAt: date(0), inviterId: "user-a", id };
    case "team": return { name: label, memberCount: 0, organizationId: "source-parent", createdAt: date(0), updatedAt: date(0), id };
    case "organizationRole": return { organizationId: "source-parent", role: label, permission: "{}", createdAt: date(0), updatedAt: date(0), id };
  }
}

export function build(options: BetterAuthOptions, model?: Model, fields: Policies = {}, pluginOptions: Parameters<typeof organization>[0] = {}) {
  const schema = Object.fromEntries(models.map(name => [name, { fields: {
    createdAt: { type: "date" as const, transform: { input: () => date(0) } },
    ...(name === "team" || name === "organizationRole" ? { updatedAt: { type: "date" as const, onUpdate: () => date(0) } } : {}),
    ...(name === model ? fields : {}),
  } }]));
  return betterAuth({ ...options, plugins: [organization({ ...pluginOptions,
    teams: { ...pluginOptions?.teams, enabled: true },
    dynamicAccessControl: { ...pluginOptions?.dynamicAccessControl, enabled: true },
  }), {
    id: "organization-live-source-fields", schema,
  }] });
}

export async function fixture(backend: Backend, name: string) {
  const fixture = await setup(backend, { name, route: "cancel", dynamicAccessControl: true });
  for (const id of ["source-parent", "other"]) {
    await fixture.context.adapter.create({ model: "organization", forceAllowId: true, data: {
      id, name: id, slug: id, logo: null, metadata: "{}", createdAt: date(0),
    } });
  }
  const writer = (await build(fixture.options).$context).adapter;
  return { ...fixture, writer };
}
export type Adapter = Awaited<ReturnType<typeof build>["$context"]>["adapter"];
export const create = (adapter: Adapter, model: Model, id: string, label: string) => adapter.create({ model, forceAllowId: true, data: visible(model, id, label) });
export const update = (adapter: Adapter, model: Model, id: string) => adapter.update({ model, where: whereId(id), update: updateData(model) });
export const point = (adapter: Adapter, model: Model, id: string) => adapter.findOne({ model, where: whereId(id) });
export const list = (adapter: Adapter, model: Model) => adapter.findMany({ model, where: model === "organization"
  ? [{ field: "id", value: ["source-a", "source-b", "source-c"], operator: "in" }]
  : [{ field: "organizationId", value: "source-parent" }, ...(model === "organizationRole"
    ? [{ field: "role", value: ["First", "Second", "Third"], operator: "in" as const }] : [])],
});
export const mutate = (adapter: Adapter, model: Model, id: string) => adapter.update({ model, where: whereId(id), update: { [late(model)]: changed(model) } });

export function replace(snapshot: Record<string, Fields[]>, model: Model, id: string, rows: Fields[]) {
  snapshot[model] = [...snapshot[model].filter(row => row.id !== id), ...rows]
    .toSorted((left, right) => String(left.id).localeCompare(String(right.id)));
}
