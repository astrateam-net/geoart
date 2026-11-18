import { beforeEach, describe, expect, it, vi } from "vitest";
import { oidcLoginURL, redirectToOIDCLogin } from "./oidcLogin";

function fakeLocation(pathname, search) {
  return { pathname, search, assign: vi.fn() };
}

describe("oidcLoginURL", () => {
  it("encodes the current path and query as the redirect", () => {
    expect(oidcLoginURL(fakeLocation("/reports/1", "?x=1&y=2"))).toBe(
      "/api/v1/oidc/login?redirect=%2Freports%2F1%3Fx%3D1%26y%3D2",
    );
  });
});

describe("redirectToOIDCLogin", () => {
  beforeEach(() => window.sessionStorage.clear());

  it("navigates to login on the first 401", () => {
    const location = fakeLocation("/device/authorize", "?device_id=d1");
    expect(redirectToOIDCLogin(location, 1000000)).toBe(true);
    expect(location.assign).toHaveBeenCalledWith("/api/v1/oidc/login?redirect=%2Fdevice%2Fauthorize%3Fdevice_id%3Dd1");
  });

  it("stops a loop when the session did not take", () => {
    const location = fakeLocation("/", "");
    redirectToOIDCLogin(location, 1000000);
    expect(redirectToOIDCLogin(location, 1010000)).toBe(false);
    expect(location.assign).toHaveBeenCalledTimes(1);
  });

  it("retries once the window has passed", () => {
    const location = fakeLocation("/", "");
    redirectToOIDCLogin(location, 1000000);
    expect(redirectToOIDCLogin(location, 1040000)).toBe(true);
  });
});
