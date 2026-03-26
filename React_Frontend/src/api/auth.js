import axios from "axios";
import * as Cookie from "../utils/cookie";

export const getAuthCookies = () => {
  const username = Cookie.get("username");
  const email = Cookie.get("email");
  const accessToken = Cookie.get("accessToken");
  const refreshToken = Cookie.get("refreshToken");

  return {
    username,
    email,
    refreshToken,
    accessToken,
  };
};

const API_BASE_URL = import.meta.env.VITE_API_URL;

// ---------------------------------------------------------------------------
// Auth API calls
// ---------------------------------------------------------------------------

export const signInUser = async ({ email, password, hcaptcha_response }) => {
  const res = await axios.post(
    `${API_BASE_URL}/api/v1/login/`,
    { email, password, hcaptcha_response },
    { headers: { "Content-Type": "application/json" } }
  );
  return res.data;
};

/**
 * Called at the TOTP verify step (user already has TOTP enabled).
 * Requires the pre_auth_token issued after the password step.
 */
export const verifyTOTP = async ({ email, totp_token, pre_auth_token }) => {
  const res = await axios.post(
    `${API_BASE_URL}/api/v1/login/totp/verify/`,
    { email, totp_token, pre_auth_token },
    { headers: { "Content-Type": "application/json" } }
  );
  return res.data;
};

/**
 * Called at the TOTP setup step (first-time TOTP enrollment).
 * Requires the pre_auth_token issued after the password step.
 */
export const setupTOTP = async ({ email, totp_token, pre_auth_token }) => {
  const res = await axios.post(
    `${API_BASE_URL}/api/v1/login/totp/setup/`,
    { email, totp_token, pre_auth_token },
    { headers: { "Content-Type": "application/json" } }
  );
  return res.data;
};

export const signOutUser = async () => {
  const authcookies = getAuthCookies();

  try {
    const res = await axios.post(
      `${API_BASE_URL}/api/v1/login/logout/`,
      { refresh: authcookies.refreshToken },
      {
        headers: {
          Authorization: `Bearer ${authcookies.accessToken}`,
          "Content-Type": "application/json",
        },
      }
    );
    return res.data;
  } catch (error) {
    console.error(error.response?.data || error.message);
    throw error;
  }
};

// ---------------------------------------------------------------------------
// JWT helpers
// ---------------------------------------------------------------------------

/**
 * Decodes the payload of a JWT (without verifying the signature).
 * Returns null if the token is missing or malformed.
 */
const decodeJWTPayload = (token) => {
  try {
    const base64 = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(base64));
  } catch {
    return null;
  }
};

/**
 * Returns the number of milliseconds until the access token expires.
 * Falls back to 0 (already expired) if the token is missing or undecodable.
 */
const msUntilExpiry = (token) => {
  const payload = decodeJWTPayload(token);
  if (!payload?.exp) return 0;
  return payload.exp * 1000 - Date.now();
};

// ---------------------------------------------------------------------------
// Token refresh — scheduled ahead of access-token expiry
// ---------------------------------------------------------------------------

/**
 * How many milliseconds before the access token's `exp` we trigger a refresh.
 * Refreshing 60 s early gives plenty of buffer for network latency.
 */
const REFRESH_BUFFER_MS = 10 * 1000; // 10 seconds

/** Holds the id returned by setTimeout so it can be cancelled on logout. */
let _refreshTimeoutId = null;

/**
 * Silently refreshes the access token using the stored refresh token.
 * Updates the accessToken cookie in-place on success, then immediately
 * schedules the next refresh based on the new token's expiry.
 * Clears all auth cookies and redirects to /login if the refresh token has
 * expired or is invalid (i.e. the session is truly over).
 */
export const refreshAccessToken = async () => {
  const { refreshToken, accessToken } = getAuthCookies();
  if (!refreshToken) return;

  try {
    const res = await axios.post(
      `${API_BASE_URL}/api/v1/login/refresh/`,
      { refresh: refreshToken },
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
      }
    );

    // Both tokens are rotated on each refresh — update both cookies
    Cookie.set("accessToken", res.data.access, 0);
    Cookie.set("refreshToken", res.data.refresh, 0);

    // Schedule the next refresh based on the new access token's actual expiry
    scheduleTokenRefresh(res.data.access);
  } catch (error) {
    // Refresh token is expired or revoked — force re-login
    console.warn("Token refresh failed, logging out:", error.response?.data || error.message);
    stopTokenRefresh();
    deleteAuthCookies();
    window.location.href = "/login";
  }
};

/**
 * Schedules a single refresh to fire `REFRESH_BUFFER_MS` before the
 * access token expires. Any previously pending refresh is cancelled first.
 *
 * @param {string} accessToken - The current JWT access token.
 */
const scheduleTokenRefresh = (accessToken) => {
  // Cancel any existing scheduled refresh
  if (_refreshTimeoutId !== null) {
    clearTimeout(_refreshTimeoutId);
    _refreshTimeoutId = null;
  }

  const delay = msUntilExpiry(accessToken) - REFRESH_BUFFER_MS;

  if (delay <= 0) {
    // Token is already expired or expiring imminently — refresh right away
    console.warn("Access token is expiring imminently, refreshing now.");
    refreshAccessToken();
    return;
  }

  console.debug(`Next token refresh scheduled in ${Math.round(delay / 1000)}s`);
  _refreshTimeoutId = setTimeout(refreshAccessToken, delay);
};

/**
 * Starts the proactive refresh cycle by scheduling the first refresh based
 * on the current access token's expiry. Call this once after a successful
 * login (replaces the old fixed-interval approach).
 *
 * @param {string} accessToken - The access token received at login.
 * @returns {void}
 */
export const startTokenRefreshInterval = (accessToken) => {
  scheduleTokenRefresh(accessToken);
};

/**
 * Cancels any pending scheduled token refresh. Call this on logout.
 */
export const stopTokenRefresh = () => {
  if (_refreshTimeoutId !== null) {
    clearTimeout(_refreshTimeoutId);
    _refreshTimeoutId = null;
  }
};

// ---------------------------------------------------------------------------
// Cookie helpers
// ---------------------------------------------------------------------------

export const setAuthCookies = ({
  username,
  email,
  refreshToken,
  accessToken,
  expiry,
}) => {
  if (username) Cookie.set("username", `${username}`, expiry);
  if (email) Cookie.set("email", `${email}`, expiry);
  if (refreshToken) Cookie.set("refreshToken", `${refreshToken}`, expiry);
  if (accessToken) Cookie.set("accessToken", `${accessToken}`, expiry);
};

export const deleteAuthCookies = () => {
  Cookie.erase("username");
  Cookie.erase("email");
  Cookie.erase("refreshToken");
  Cookie.erase("accessToken");
};

// ---------------------------------------------------------------------------
// Auto-logout on tab/browser close (not on refresh)
// ---------------------------------------------------------------------------

/**
 * On first load, mark the session as "alive" in sessionStorage.
 * sessionStorage is cleared automatically when the tab is closed,
 * but survives a page refresh — so we only wipe cookies on a true
 * first load where the flag is absent (meaning the tab was freshly opened
 * after being closed).
 */
export const initSessionGuard = () => {
  const SESSION_KEY = "session_alive";

  if (!sessionStorage.getItem(SESSION_KEY)) {
    // Tab was closed and reopened (or first ever visit) — clear stale cookies
    deleteAuthCookies();
    stopTokenRefresh();
  }

  // Mark session as alive for this tab's lifetime
  sessionStorage.setItem(SESSION_KEY, "1");
};