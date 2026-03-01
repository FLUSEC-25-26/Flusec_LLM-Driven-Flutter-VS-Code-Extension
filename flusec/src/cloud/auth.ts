// src/cloud/auth.ts
//
// Handles FluSec Web Platform authentication from VS Code.
// Stores JWT and team info securely using VS Code SecretStorage.

import * as vscode from 'vscode';
import fetch from 'node-fetch';

const SECRET_KEY_TOKEN = 'flusec.jwt';
const SECRET_KEY_TEAM_ID = 'flusec.teamId';

// ─── Token helpers ────────────────────────────────────────────────────────────

export async function getStoredToken(context: vscode.ExtensionContext): Promise<string | undefined> {
    return context.secrets.get(SECRET_KEY_TOKEN);
}

export async function getStoredTeamId(context: vscode.ExtensionContext): Promise<string | undefined> {
    return context.secrets.get(SECRET_KEY_TEAM_ID);
}

async function storeSession(context: vscode.ExtensionContext, token: string, teamId: string) {
    await context.secrets.store(SECRET_KEY_TOKEN, token);
    await context.secrets.store(SECRET_KEY_TEAM_ID, teamId);
}

export async function clearSession(context: vscode.ExtensionContext) {
    await context.secrets.delete(SECRET_KEY_TOKEN);
    await context.secrets.delete(SECRET_KEY_TEAM_ID);
}

// ─── Login flow ───────────────────────────────────────────────────────────────

export async function loginToTeam(context: vscode.ExtensionContext) {
    const config = vscode.workspace.getConfiguration('flusec');
    const endpoint = (config.get<string>('webApiEndpoint') ?? 'http://localhost:3001').replace(/\/$/, '');

    // Step 1 — get email
    const email = await vscode.window.showInputBox({
        prompt: 'Enter your FluSec account email',
        placeHolder: 'you@example.com',
        ignoreFocusOut: true,
    });
    if (!email) { return; }

    // Step 2 — get password
    const password = await vscode.window.showInputBox({
        prompt: 'Enter your FluSec account password',
        password: true,
        ignoreFocusOut: true,
    });
    if (!password) { return; }

    // Step 3 — sign in via Supabase REST (direct, no web redirect needed)
    await vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: 'FLUSEC: Signing in…', cancellable: false },
        async (progress) => {
            try {
                // Use Supabase Auth REST endpoint directly
                const supabaseUrl = config.get<string>('supabaseUrl') ?? '';
                const supabaseAnonKey = config.get<string>('supabaseAnonKey') ?? '';

                if (!supabaseUrl || !supabaseAnonKey) {
                    vscode.window.showErrorMessage(
                        'FLUSEC: Set flusec.supabaseUrl and flusec.supabaseAnonKey in VS Code settings first.'
                    );
                    return;
                }

                const signInRes = await fetch(`${supabaseUrl}/auth/v1/token?grant_type=password`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'apikey': supabaseAnonKey,
                    },
                    body: JSON.stringify({ email, password }),
                });

                if (!signInRes.ok) {
                    const err = await signInRes.json() as { error_description?: string };
                    vscode.window.showErrorMessage(`FLUSEC: Login failed — ${err.error_description ?? 'Invalid credentials'}`);
                    return;
                }

                const session = await signInRes.json() as { access_token: string };
                const jwt = session.access_token;

                progress.report({ message: 'Fetching your team…' });

                // Step 4 — get user's team membership from your backend
                const meRes = await fetch(`${endpoint}/api/auth/me`, {
                    headers: { Authorization: `Bearer ${jwt}` },
                });

                if (!meRes.ok) {
                    vscode.window.showErrorMessage('FLUSEC: Could not fetch profile. Is the backend running?');
                    return;
                }

                // Step 5 — prompt for team ID (or we can auto-detect later)
                const teamId = await vscode.window.showInputBox({
                    prompt: 'Enter your Team ID (found in Team Settings on the web app)',
                    placeHolder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
                    ignoreFocusOut: true,
                });
                if (!teamId) { return; }

                await storeSession(context, jwt, teamId.trim());
                vscode.window.showInformationMessage(
                    `✅ FLUSEC: Logged in! Run "FluSec: Sync Findings to Team" to upload your findings.`
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
