import * as vscode from 'vscode';
import fetch from 'node-fetch';
import { CONFIG } from '../config';

const SECRET_KEY_TOKEN = 'flusec.jwt';
const SECRET_KEY_TEAM_ID = 'flusec.teamId';
const SECRET_KEY_TEAM_CODE = 'flusec.teamCode';
const SECRET_KEY_TEAM_NAME = 'flusec.teamName';
const SECRET_KEY_TEAM_ROLE = 'flusec.teamRole';

type TeamRole = 'leader' | 'member' | 'viewer';

type SupabasePasswordSession = {
  access_token: string;
};

type ResolveCodePayload = {
  team_id: string;
  team_code: string;
  team_name: string;
  description?: string | null;
  role: TeamRole;
};

type ResolveCodeSuccessResponse = {
  data: ResolveCodePayload;
};

type ErrorResponse = {
  error?: string;
  error_description?: string;
};

async function readJsonSafe<T>(res: fetch.Response): Promise<T | null> {
  try {
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

// ─── Stored session helpers ───────────────────────────────────────────────────

export async function getStoredToken(
  context: vscode.ExtensionContext
): Promise<string | undefined> {
  return context.secrets.get(SECRET_KEY_TOKEN);
}

export async function getStoredTeamId(
  context: vscode.ExtensionContext
): Promise<string | undefined> {
  return context.secrets.get(SECRET_KEY_TEAM_ID);
}

export async function getStoredTeamCode(
  context: vscode.ExtensionContext
): Promise<string | undefined> {
  return context.secrets.get(SECRET_KEY_TEAM_CODE);
}

export async function getStoredTeamName(
  context: vscode.ExtensionContext
): Promise<string | undefined> {
  return context.secrets.get(SECRET_KEY_TEAM_NAME);
}

export async function getStoredTeamRole(
  context: vscode.ExtensionContext
): Promise<string | undefined> {
  return context.secrets.get(SECRET_KEY_TEAM_ROLE);
}

async function storeSession(
  context: vscode.ExtensionContext,
  token: string,
  teamId: string,
  teamCode: string,
  teamName: string,
  role: string
) {
  await context.secrets.store(SECRET_KEY_TOKEN, token);
  await context.secrets.store(SECRET_KEY_TEAM_ID, teamId);
  await context.secrets.store(SECRET_KEY_TEAM_CODE, teamCode);
  await context.secrets.store(SECRET_KEY_TEAM_NAME, teamName);
  await context.secrets.store(SECRET_KEY_TEAM_ROLE, role);
}

export async function clearSession(context: vscode.ExtensionContext) {
  await context.secrets.delete(SECRET_KEY_TOKEN);
  await context.secrets.delete(SECRET_KEY_TEAM_ID);
  await context.secrets.delete(SECRET_KEY_TEAM_CODE);
  await context.secrets.delete(SECRET_KEY_TEAM_NAME);
  await context.secrets.delete(SECRET_KEY_TEAM_ROLE);
}

// ─── Login flow ───────────────────────────────────────────────────────────────

export async function loginToTeam(context: vscode.ExtensionContext) {
  const endpoint = CONFIG.WEB_API_ENDPOINT.replace(/\/$/, '');
  const supabaseUrl = CONFIG.SUPABASE_URL.replace(/\/$/, '');
  const supabaseAnonKey = CONFIG.SUPABASE_ANON_KEY;

  const email = await vscode.window.showInputBox({
    prompt: 'Enter your FluSec account email',
    placeHolder: 'you@example.com',
    ignoreFocusOut: true,
  });
  if (!email) {
    return;
  }

  const password = await vscode.window.showInputBox({
    prompt: 'Enter your FluSec account password',
    password: true,
    ignoreFocusOut: true,
  });
  if (!password) {
    return;
  }

  const teamCodeInput = await vscode.window.showInputBox({
    prompt: 'Enter your Team ID (team code shown in the web app)',
    placeHolder: 'FTA1008',
    ignoreFocusOut: true,
  });
  if (!teamCodeInput) {
    return;
  }

  const teamCode = teamCodeInput.trim().toUpperCase();

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: 'FLUSEC: Signing in…',
      cancellable: false,
    },
    async (progress) => {
      try {
        progress.report({ message: 'Signing in with Supabase…' });

        const signInRes = await fetch(
          `${supabaseUrl}/auth/v1/token?grant_type=password`,
          {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              apikey: supabaseAnonKey,
            },
            body: JSON.stringify({
              email: email.trim(),
              password,
            }),
          }
        );

        if (!signInRes.ok) {
          const err = await readJsonSafe<ErrorResponse>(signInRes);
          vscode.window.showErrorMessage(
            `FLUSEC: Login failed — ${
              err?.error_description ?? err?.error ?? 'Invalid credentials'
            }`
          );
          return;
        }

        const session = (await signInRes.json()) as SupabasePasswordSession;
        const jwt = session.access_token;

        progress.report({ message: `Resolving team code ${teamCode}…` });

        const resolveRes = await fetch(`${endpoint}/api/teams/resolve-code`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${jwt}`,
          },
          body: JSON.stringify({
            team_code: teamCode,
          }),
        });

        if (!resolveRes.ok) {
          const err = await readJsonSafe<ErrorResponse>(resolveRes);
          vscode.window.showErrorMessage(
            `FLUSEC: Could not resolve team code — ${
              err?.error ?? err?.error_description ?? 'Team not found or access denied'
            }`
          );
          return;
        }

        const resolveJson =
          await readJsonSafe<ResolveCodeSuccessResponse>(resolveRes);

        if (!resolveJson?.data) {
          vscode.window.showErrorMessage(
            'FLUSEC: Team lookup returned an invalid response.'
          );
          return;
        }

        const resolved = resolveJson.data;

        await storeSession(
          context,
          jwt,
          resolved.team_id,
          resolved.team_code,
          resolved.team_name,
          resolved.role
        );

        vscode.window.showInformationMessage(
          `FLUSEC: Logged in to ${resolved.team_name} (${resolved.team_code}) as ${resolved.role}.`
        );
      } catch (e) {
        vscode.window.showErrorMessage('FLUSEC: Login error — ' + String(e));
      }
    }
  );
}

// ─── Logout ───────────────────────────────────────────────────────────────────

export async function logoutFromTeam(context: vscode.ExtensionContext) {
  await clearSession(context);
  vscode.window.showInformationMessage('FLUSEC: Logged out from team.');
}