# frozen_string_literal: true

# name: disconite-resonite-oidc
# about: Log in with a Resonite account using OAuth 2.0 / OpenID Connect (account.resonite.com).
# version: 2.0
# authors: Disconite (Resonite fork; originally David Taylor / Discourse OpenID Connect)
# url: https://github.com/discourse/discourse/tree/main/plugins/discourse-openid-connect

enabled_site_setting :resonite_oauth_enabled

register_svg_icon "disconite-resonite-oidc"
register_svg_icon "resonite"

register_asset "stylesheets/common/resonite-oauth.scss"

require_relative "lib/resonite_oauth_faraday_formatter"
require_relative "lib/resonite_asset_url"
require_relative "lib/omniauth_open_id_connect"
require_relative "lib/omniauth_resonite_open_id_connect"
require_relative "lib/resonite_oauth_authenticator"

GlobalSetting.add_default :resonite_oauth_request_timeout_seconds, 10

register_site_setting_area("resonite")
register_admin_config_login_route("resonite")

# RP-initiated logout
# https://openid.net/specs/openid-connect-rpinitiated-1_0.html
on(:before_session_destroy) do |data|
  next if !SiteSetting.resonite_oauth_rp_initiated_logout

  authenticator = ResoniteOAuthAuthenticator.new

  resonite_record = data[:user]&.user_associated_accounts&.find_by(provider_name: "resonite")
  if !resonite_record
    authenticator.resonite_oauth_log "Logout: No resonite user_associated_account record for user"
    next
  end

  token = resonite_record.extra["id_token"]
  if !token
    authenticator.resonite_oauth_log "Logout: No resonite id_token in user_associated_account record"
    next
  end

  discovery = authenticator.discovery_document
  if discovery.blank? || !discovery.is_a?(Hash)
    authenticator.resonite_oauth_log(
      "Logout: Discovery document unavailable",
      error: true,
    )
    next
  end

  end_session_endpoint = discovery["end_session_endpoint"].presence
  if !end_session_endpoint
    authenticator.resonite_oauth_log "Logout: No end_session_endpoint found in discovery document",
                                     error: true
    next
  end

  begin
    uri = URI.parse(end_session_endpoint)
  rescue URI::Error
    authenticator.resonite_oauth_log "Logout: unable to parse end_session_endpoint #{end_session_endpoint}",
                                     error: true
  end

  authenticator.resonite_oauth_log "Logout: Redirecting user_id=#{data[:user].id} to end_session_endpoint"

  params = URI.decode_www_form(String(uri.query))

  params << ["id_token_hint", token]

  if SiteSetting.resonite_oauth_rp_initiated_logout_include_client_id &&
       SiteSetting.resonite_oauth_client_id.present?
    params << ["client_id", SiteSetting.resonite_oauth_client_id]
  end

  post_logout_redirect = SiteSetting.resonite_oauth_rp_initiated_logout_redirect.presence
  params << ["post_logout_redirect_uri", post_logout_redirect] if post_logout_redirect

  uri.query = URI.encode_www_form(params)
  data[:redirect_url] = uri.to_s
end

auth_provider authenticator: ResoniteOAuthAuthenticator.new, icon: "resonite"
