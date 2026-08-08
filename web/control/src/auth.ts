const authSessionKey = "aor.auth.session.v1";
const oauthStateKey = "aor.oauth.state.v1";
const oauthVerifierKey = "aor.oauth.verifier.v1";

export interface AuthConfig {
  issuer: string;
  authorizationEndpoint: string;
  clientId: string;
  redirectPath: string;
  tokenEndpoint: string;
  scopes: string[];
}

export interface AuthSession {
  accessToken: string;
  refreshToken?: string;
  expiresAt: number;
}

interface TokenResponse {
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
  error?: string;
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function randomValue(length = 64): string {
  return base64Url(crypto.getRandomValues(new Uint8Array(length)));
}

async function codeChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64Url(new Uint8Array(digest));
}

async function exchangeToken(config: AuthConfig, body: URLSearchParams): Promise<AuthSession> {
  const response = await fetch(config.tokenEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  const token = (await response.json()) as TokenResponse;
  if (!response.ok || !token.access_token) {
    throw new Error(token.error || "登录服务暂时不可用");
  }
  const session: AuthSession = {
    accessToken: token.access_token,
    refreshToken: token.refresh_token,
    expiresAt: Date.now() + Math.max(30, token.expires_in ?? 300) * 1000,
  };
  saveSession(session);
  return session;
}

export async function loadAuthConfig(): Promise<AuthConfig> {
  const response = await fetch("/ui/config", { headers: { Accept: "application/json" } });
  if (!response.ok) {
    throw new Error("无法读取登录配置");
  }
  return (await response.json()) as AuthConfig;
}

export async function beginLogin(config: AuthConfig): Promise<void> {
  const verifier = randomValue(64);
  const state = randomValue(32);
  sessionStorage.setItem(oauthVerifierKey, verifier);
  sessionStorage.setItem(oauthStateKey, state);
  const redirectUri = new URL(config.redirectPath, window.location.origin).toString();
  const authorization = new URL(config.authorizationEndpoint);
  authorization.searchParams.set("client_id", config.clientId);
  authorization.searchParams.set("redirect_uri", redirectUri);
  authorization.searchParams.set("response_type", "code");
  authorization.searchParams.set("scope", config.scopes.join(" "));
  authorization.searchParams.set("state", state);
  authorization.searchParams.set("code_challenge", await codeChallenge(verifier));
  authorization.searchParams.set("code_challenge_method", "S256");
  window.location.assign(authorization.toString());
}

export async function completeLogin(config: AuthConfig): Promise<AuthSession | undefined> {
  const current = new URL(window.location.href);
  const code = current.searchParams.get("code");
  const returnedState = current.searchParams.get("state");
  const oauthError = current.searchParams.get("error");
  if (!code && !oauthError) {
    return undefined;
  }
  if (oauthError) {
    throw new Error(current.searchParams.get("error_description") || oauthError);
  }
  const verifier = sessionStorage.getItem(oauthVerifierKey);
  const expectedState = sessionStorage.getItem(oauthStateKey);
  if (!verifier || !returnedState || returnedState !== expectedState || !code) {
    throw new Error("登录回调校验失败");
  }
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    code_verifier: verifier,
    redirect_uri: new URL(config.redirectPath, window.location.origin).toString(),
  });
  const session = await exchangeToken(config, body);
  sessionStorage.removeItem(oauthVerifierKey);
  sessionStorage.removeItem(oauthStateKey);
  window.history.replaceState({}, document.title, "/ui/");
  return session;
}

export function loadSession(): AuthSession | undefined {
  const raw = sessionStorage.getItem(authSessionKey);
  if (!raw) {
    return undefined;
  }
  try {
    const session = JSON.parse(raw) as AuthSession;
    if (!session.accessToken || !Number.isFinite(session.expiresAt)) {
      throw new Error("invalid session");
    }
    return session;
  } catch {
    sessionStorage.removeItem(authSessionKey);
    return undefined;
  }
}

export function saveSession(session: AuthSession): void {
  sessionStorage.setItem(authSessionKey, JSON.stringify(session));
}

export function clearSession(): void {
  sessionStorage.removeItem(authSessionKey);
  sessionStorage.removeItem(oauthStateKey);
  sessionStorage.removeItem(oauthVerifierKey);
}

export async function usableSession(config: AuthConfig, session: AuthSession): Promise<AuthSession> {
  if (session.expiresAt > Date.now() + 30_000) {
    return session;
  }
  if (!session.refreshToken) {
    clearSession();
    throw new Error("登录已过期");
  }
  const refreshed = await exchangeToken(
    config,
    new URLSearchParams({ grant_type: "refresh_token", refresh_token: session.refreshToken }),
  );
  if (!refreshed.refreshToken) {
    refreshed.refreshToken = session.refreshToken;
    saveSession(refreshed);
  }
  return refreshed;
}
