const loginAttemptKey = 'oidcLoginAttemptAt'
// A second 401 within this window means the session did not take; show the error instead of looping.
const loginRetryWindowMs = 30 * 1000

// oidcLoginURL returns the server login endpoint that brings the browser back to the given location.
export function oidcLoginURL (location = window.location) {
  return `/api/v1/oidc/login?redirect=${encodeURIComponent(location.pathname + location.search)}`
}

// redirectToOIDCLogin starts a full-page login and returns false when one just failed to produce a session.
export function redirectToOIDCLogin (location = window.location, now = Date.now()) {
  let lastAttempt = 0
  try {
    lastAttempt = Number(window.sessionStorage.getItem(loginAttemptKey)) || 0
    window.sessionStorage.setItem(loginAttemptKey, String(now))
  } catch (e) {
    // Storage can be unavailable (private mode); losing the loop guard is better than blocking login.
  }
  if (now - lastAttempt < loginRetryWindowMs) {
    return false
  }
  location.assign(oidcLoginURL(location))
  return true
}

// oidcLogout ends the server session, then leaves through the provider logout page when it has one.
export async function oidcLogout () {
  let logoutUrl = ''
  try {
    const res = await window.fetch('/api/v1/oidc/logout', { method: 'POST', credentials: 'same-origin' })
    if (res.ok) {
      logoutUrl = (await res.json()).logoutUrl || ''
    }
  } catch (e) {
    // The page reload below re-checks the session either way.
  }
  window.location.assign(logoutUrl || '/')
}
