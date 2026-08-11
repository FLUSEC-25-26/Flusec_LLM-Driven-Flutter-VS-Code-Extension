import * as vscode from 'vscode';
import { createHash, randomBytes } from 'node:crypto';
import fetch, { Headers, type RequestInit, type Response } from 'node-fetch';
import { CONFIG } from '../config.js';

const SESSION_SECRET_KEY = 'flusec.oauth.session.v1';
const PENDING_SECRET_KEY = 'flusec.oauth.pending.v1';
const SELECTED_TEAM_KEY = 'flusec.selectedTeam.v1';

export type TeamRole = 'leader' | 'member' | 'viewer'

export interface SelectedTeam {
  id: string
  teamCode?: string | null
  name: string
  role: TeamRole
}

interface OAuthSession {
  accessToken: string
  refreshToken: string
  expiresAt: number
  tokenType: string
  scope?: string
}

interface PendingAuthorization {
  state: string
  codeVerifier: string
  redirectUri: string
  createdAt: number
}

interface TokenResponse {
  access_token?: string
  refresh_token?: string
  expires_in?: number
  token_type?: string
  scope?: string
  error?: string
  error_description?: string
}

interface ApiTeam {
  id: string
  team_code?: string | null
  name: string
  myRole?: TeamRole
  role?: TeamRole
}

interface MyTeamsResponse {
  data?: ApiTeam[]
  error?: string
}

function encodeBase64Url(value: Buffer | string): string {
  return Buffer.from(value).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function createPkce() {
  const codeVerifier = encodeBase64Url(randomBytes(48));
  const codeChallenge = encodeBase64Url(createHash('sha256').update(codeVerifier).digest());
  return { codeVerifier, codeChallenge };
}

function createState(context: vscode.ExtensionContext): string {
  const payload = {
    nonce: encodeBase64Url(randomBytes(24)),
    scheme: vscode.env.uriScheme === 'vscode-insiders' ? 'vscode-insiders' : 'vscode',
    extensionId: context.extension.id,
  };
  return encodeBase64Url(JSON.stringify(payload));
}

async function parseJson<T>(response: Response): Promise<T> {
  const text = await response.text();
  if (!text) { return {} as T; }
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new Error(`Unexpected server response (${response.status})`);
  }
}

async function readSession(context: vscode.ExtensionContext): Promise<OAuthSession | undefined> {
  const raw = await context.secrets.get(SESSION_SECRET_KEY);
  if (!raw) { return undefined; }
  try {
    const parsed = JSON.parse(raw) as OAuthSession;
    if (!parsed.accessToken || !parsed.refreshToken || !parsed.expiresAt) { return undefined; }
    return parsed;
  } catch {
    return undefined;
  }
}

async function storeSession(context: vscode.ExtensionContext, session: OAuthSession) {
  await context.secrets.store(SESSION_SECRET_KEY, JSON.stringify(session));
}

async function exchangeAuthorizationCode(
  context: vscode.ExtensionContext,
  code: string,
  pending: PendingAuthorization
) {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    client_id: CONFIG.OAUTH_CLIENT_ID,
    redirect_uri: pending.redirectUri,
    code_verifier: pending.codeVerifier,
  });

  const response = await fetch(`${CONFIG.SUPABASE_URL}/auth/v1/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  const data = await parseJson<TokenResponse>(response);
  if (!response.ok || !data.access_token || !data.refresh_token) {
    throw new Error(data.error_description ?? data.error ?? 'OAuth code exchange failed');
  }

  await storeSession(context, {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    expiresAt: Date.now() + Math.max(60, Number(data.expires_in ?? 3600)) * 1000,
    tokenType: data.token_type ?? 'Bearer',
    scope: data.scope,
  });
}

async function refreshOAuthSession(context: vscode.ExtensionContext, force = false): Promise<OAuthSession> {
  const existing = await readSession(context);
  if (!existing) { throw new Error('FLUSEC account is not connected.'); }

  if (!force && existing.expiresAt > Date.now() + 90_000) { return existing; }

  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: existing.refreshToken,
    client_id: CONFIG.OAUTH_CLIENT_ID,
  });
  const response = await fetch(`${CONFIG.SUPABASE_URL}/auth/v1/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  const data = await parseJson<TokenResponse>(response);
  if (!response.ok || !data.access_token) {
    await clearSession(context);
    throw new Error(data.error_description ?? data.error ?? 'FLUSEC session expired. Connect your account again.');
  }

  const next: OAuthSession = {
    accessToken: data.access_token,
    refreshToken: data.refresh_token ?? existing.refreshToken,
    expiresAt: Date.now() + Math.max(60, Number(data.expires_in ?? 3600)) * 1000,
    tokenType: data.token_type ?? existing.tokenType ?? 'Bearer',
    scope: data.scope ?? existing.scope,
  };
  await storeSession(context, next);
  return next;
}

export async function getStoredToken(context: vscode.ExtensionContext): Promise<string | undefined> {
  try {
    return (await refreshOAuthSession(context)).accessToken;
  } catch {
    return undefined;
  }
}

export async function getSelectedTeam(context: vscode.ExtensionContext): Promise<SelectedTeam | undefined> {
  return context.workspaceState.get<SelectedTeam>(SELECTED_TEAM_KEY);
}

export async function getStoredTeamId(context: vscode.ExtensionContext): Promise<string | undefined> {
  return (await getSelectedTeam(context))?.id;
}

export async function getStoredTeamCode(context: vscode.ExtensionContext): Promise<string | undefined> {
  return (await getSelectedTeam(context))?.teamCode ?? undefined;
}

export async function getStoredTeamName(context: vscode.ExtensionContext): Promise<string | undefined> {
  return (await getSelectedTeam(context))?.name;
}

export async function getStoredTeamRole(context: vscode.ExtensionContext): Promise<string | undefined> {
  return (await getSelectedTeam(context))?.role;
}

export async function clearSession(context: vscode.ExtensionContext) {
  await Promise.all([
    context.secrets.delete(SESSION_SECRET_KEY),
    context.secrets.delete(PENDING_SECRET_KEY),
    // Remove credentials from pre-OAuth FLUSEC builds as part of the migration.
    context.secrets.delete('flusec.jwt'),
    context.secrets.delete('flusec.teamId'),
    context.secrets.delete('flusec.teamCode'),
    context.secrets.delete('flusec.teamName'),
    context.secrets.delete('flusec.teamRole'),
    context.workspaceState.update(SELECTED_TEAM_KEY, undefined),
  ]);
}

export async function authenticatedFetch(
  context: vscode.ExtensionContext,
  url: string,
  options: RequestInit = {},
  retry = true
): Promise<Response> {
  const session = await refreshOAuthSession(context);
  const headers = new Headers(options.headers);
  headers.set('Authorization', `Bearer ${session.accessToken}`);
  const response = await fetch(url, { ...options, headers });

  if (response.status === 401 && retry) {
    const refreshed = await refreshOAuthSession(context, true);
    const retryHeaders = new Headers(options.headers);
    retryHeaders.set('Authorization', `Bearer ${refreshed.accessToken}`);
    return fetch(url, { ...options, headers: retryHeaders });
  }
  return response;
}

export async function selectTeam(context: vscode.ExtensionContext, showConfirmation = true): Promise<SelectedTeam | undefined> {
  const response = await authenticatedFetch(context, `${CONFIG.WEB_API_ENDPOINT}/api/v1/teams/my-teams`);
  const payload = await parseJson<MyTeamsResponse>(response);
  if (!response.ok) { throw new Error(payload.error ?? 'Could not load FLUSEC teams'); }

  const teams = payload.data ?? [];
  if (teams.length === 0) {
    const choice = await vscode.window.showInformationMessage(
      'FLUSEC: Your account does not belong to a team yet. Create or join a team in the web app.',
      'Open FLUSEC Web App'
    );
    if (choice) { await vscode.env.openExternal(vscode.Uri.parse(`${CONFIG.WEB_APP_URL}/team`)); }
    return undefined;
  }

  const selected = await vscode.window.showQuickPick(
    teams.map((team) => ({
      label: team.name,
      description: team.team_code ? `${team.team_code} · ${team.myRole ?? team.role ?? 'member'}` : (team.myRole ?? team.role ?? 'member'),
      team,
    })),
    { title: 'FLUSEC: Select Team for This Workspace', placeHolder: 'Choose the team whose policies and findings apply to this workspace' }
  );
  if (!selected) { return undefined; }

  const value: SelectedTeam = {
    id: selected.team.id,
    teamCode: selected.team.team_code ?? null,
    name: selected.team.name,
    role: selected.team.myRole ?? selected.team.role ?? 'member',
  };
  await context.workspaceState.update(SELECTED_TEAM_KEY, value);
  if (showConfirmation) {
    vscode.window.showInformationMessage(`FLUSEC: This workspace is connected to ${value.name} as ${value.role}.`);
  }
  return value;
}

async function handleUri(context: vscode.ExtensionContext, uri: vscode.Uri) {
  if (uri.path !== '/auth-complete' && uri.path !== 'auth-complete') { return; }

  const params = new URLSearchParams(uri.query);
  const returnedState = params.get('state') ?? '';
  const code = params.get('code') ?? '';
  const oauthError = params.get('error_description') ?? params.get('error');
  const rawPending = await context.secrets.get(PENDING_SECRET_KEY);

  if (!rawPending) {
    vscode.window.showErrorMessage('FLUSEC: No pending browser sign-in was found. Start Connect Account again.');
    return;
  }

  let pending: PendingAuthorization;
  try { pending = JSON.parse(rawPending) as PendingAuthorization; } catch {;
    await context.secrets.delete(PENDING_SECRET_KEY);
    vscode.window.showErrorMessage('FLUSEC: Stored OAuth request is invalid. Start Connect Account again.');
    return;
  }

  if (Date.now() - pending.createdAt > 10 * 60 * 1000) {
    await context.secrets.delete(PENDING_SECRET_KEY);
    vscode.window.showErrorMessage('FLUSEC: Browser sign-in expired. Start Connect Account again.');
    return;
  }
  if (!returnedState || returnedState !== pending.state) {
    await context.secrets.delete(PENDING_SECRET_KEY);
    vscode.window.showErrorMessage('FLUSEC: OAuth state validation failed. No session was stored.');
    return;
  }
  if (oauthError) {
    await context.secrets.delete(PENDING_SECRET_KEY);
    vscode.window.showErrorMessage(`FLUSEC: Authorization was not completed — ${oauthError}`);
    return;
  }
  if (!code) {
    vscode.window.showErrorMessage('FLUSEC: OAuth callback did not contain an authorization code.');
    return;
  }

  try {
    await exchangeAuthorizationCode(context, code, pending);
    await context.secrets.delete(PENDING_SECRET_KEY);
    const team = await selectTeam(context, false);
    if (team) {
      vscode.window.showInformationMessage(`FLUSEC: Account connected. Active team: ${team.name}.`);
      await vscode.commands.executeCommand('flusec.updateRulePacks');
    } else {
      vscode.window.showInformationMessage('FLUSEC: Account connected. Select a team after creating or joining one in the web app.');
    }
  } catch (error) {
    await context.secrets.delete(PENDING_SECRET_KEY);
    vscode.window.showErrorMessage(`FLUSEC: Could not complete browser sign-in — ${String(error)}`);
  }
}

export function registerAuthUriHandler(context: vscode.ExtensionContext) {
  const disposable = vscode.window.registerUriHandler({ handleUri: (uri) => handleUri(context, uri) });
  context.subscriptions.push(disposable);
  console.log(`[FLUSEC] OAuth callback extension id: ${context.extension.id}`);
}

export async function connectAccount(context: vscode.ExtensionContext) {
  if (!CONFIG.OAUTH_CLIENT_ID) {
    vscode.window.showErrorMessage('FLUSEC: Set flusec.oauthClientId before connecting your account.');
    return;
  }

  const existing = await readSession(context);
  if (existing) {
    const action = await vscode.window.showInformationMessage(
      'FLUSEC: An account is already connected.',
      'Switch Team',
      'Reconnect'
    );
    if (action === 'Switch Team') { await selectTeam(context); }
    if (action !== 'Reconnect') { return; }
    await clearSession(context);
  }

  const { codeVerifier, codeChallenge } = createPkce();
  const state = createState(context);
  const redirectUri = `${CONFIG.WEB_APP_URL}/oauth/vscode/callback`;
  const pending: PendingAuthorization = { state, codeVerifier, redirectUri, createdAt: Date.now() };
  await context.secrets.store(PENDING_SECRET_KEY, JSON.stringify(pending));

  const authorize = new URL(`${CONFIG.SUPABASE_URL}/auth/v1/oauth/authorize`);
  authorize.searchParams.set('response_type', 'code');
  authorize.searchParams.set('client_id', CONFIG.OAUTH_CLIENT_ID);
  authorize.searchParams.set('redirect_uri', redirectUri);
  authorize.searchParams.set('code_challenge', codeChallenge);
  authorize.searchParams.set('code_challenge_method', 'S256');
  authorize.searchParams.set('state', state);
  authorize.searchParams.set('scope', 'email profile');

  const opened = await vscode.env.openExternal(vscode.Uri.parse(authorize.toString()));
  if (!opened) {
    await context.secrets.delete(PENDING_SECRET_KEY);
    vscode.window.showErrorMessage('FLUSEC: Could not open the system browser.');
    return;
  }

  vscode.window.showInformationMessage('FLUSEC: Complete sign-in and authorization in your browser. VS Code will resume automatically.');
}

export async function disconnectAccount(context: vscode.ExtensionContext) {
  await clearSession(context);
  vscode.window.showInformationMessage('FLUSEC: Account disconnected from VS Code.');
}

export async function switchTeam(context: vscode.ExtensionContext) {
  try {
    await selectTeam(context);
    await vscode.commands.executeCommand('flusec.updateRulePacks');
  } catch (error) {
    vscode.window.showErrorMessage(`FLUSEC: Could not switch team — ${String(error)}`);
  }
}

// Backward-compatible command exports. The behavior is browser OAuth, not password login.
export const loginToTeam = connectAccount;
export const logoutFromTeam = disconnectAccount;
