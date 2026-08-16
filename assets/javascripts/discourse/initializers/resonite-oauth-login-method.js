import getURL from "discourse/lib/get-url";

export default {
  name: "resonite-oauth-login-method",

  initialize() {
    document.documentElement.style.setProperty(
      "--resonite-oauth-login-icon-url",
      `url("${getURL("/plugins/disconite-resonite-oidc/resonite-login-icon.svg")}")`,
    );
  },
};
