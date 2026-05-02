import { withPluginApi } from "discourse/lib/plugin-api";
import getURL from "discourse/lib/get-url";

const PLUGIN_ID = "disconite-resonite-oidc";

export default {
  name: "resonite-oauth-login-method",

  initialize() {
    document.documentElement.style.setProperty(
      "--resonite-oauth-login-icon-url",
      `url("${getURL("/plugins/disconite-resonite-oidc/resonite-login-icon.svg")}")`,
    );

    withPluginApi("1.0.0", (api) => {
      api.modifyClass("model:login-method", {
        pluginId: PLUGIN_ID,

        get icon() {
          return (
            this.icon_override ??
            this.iconOverride ??
            "user"
          );
        },
      });
    });
  },
};
