import type { APIRequestContext } from "@playwright/test";

export const dexIssuer = process.env.EBPF_DEX_ISSUER ?? "http://127.0.0.1:8081/dex";
export const apiBase = process.env.EBPF_API_BASE ?? "http://127.0.0.1:8081/api/v1";

export async function accessToken(
  request: APIRequestContext,
  username: string,
  password: string,
  clientId = "ebpf-dashboard",
): Promise<string> {
  const response = await request.post(`${dexIssuer}/token`, {
    form: {
      grant_type: "password",
      username,
      password,
      client_id: clientId,
      scope: "openid groups email profile",
    },
  });
  if (!response.ok()) {
    throw new Error(`token request failed: ${response.status()} ${await response.text()}`);
  }
  const body = (await response.json()) as { access_token?: string };
  if (!body.access_token) {
    throw new Error("token response has no access_token");
  }
  return body.access_token;
}

export async function stageAndCommit(
  request: APIRequestContext,
  token: string,
  version = 1,
): Promise<void> {
  const content = 'schema_version: 1\nengine_version: "1.0.0"\nrules: []\n';
  const headers = { Authorization: `Bearer ${token}` };
  const stage = await request.post(`${apiBase}/policies/stage`, {
    headers,
    data: { version, content, name: "default" },
  });
  if (!stage.ok()) {
    throw new Error(`stage failed: ${stage.status()} ${await stage.text()}`);
  }
  const commit = await request.post(`${apiBase}/policies/commit`, {
    headers,
    data: { version },
  });
  if (!commit.ok()) {
    throw new Error(`commit failed: ${commit.status()} ${await commit.text()}`);
  }
}
