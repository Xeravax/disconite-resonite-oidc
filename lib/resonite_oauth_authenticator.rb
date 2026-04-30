# frozen_string_literal: true

require "base64"
require "openssl"

class ResoniteOAuthAuthenticator < Auth::ManagedAuthenticator
  DISCOVERY_DOCUMENT_DEFAULT =
    "https://account.resonite.com/.well-known/openid-configuration".freeze

  def name
    "resonite"
  end

  def icon
    "disconite-resonite-oidc"
  end

  def can_revoke?
    SiteSetting.resonite_oauth_allow_association_change
  end

  def can_connect_existing_user?
    SiteSetting.resonite_oauth_allow_association_change
  end

  def enabled?
    SiteSetting.resonite_oauth_enabled
  end

  def primary_email_verified?(auth)
    raw = auth["extra"]["raw_info"]
    supplied_verified_boolean =
      if raw.is_a?(Hash)
        raw["email_verified"] || raw["isVerified"]
      end

    if supplied_verified_boolean.nil?
      true
    else
      supplied_verified_boolean == true ||
        (supplied_verified_boolean.is_a?(String) && supplied_verified_boolean.downcase == "true")
    end
  end

  def provides_groups?
    SiteSetting.resonite_oauth_groups_claim.present? ||
      SiteSetting.resonite_oauth_active_supporter_group.present?
  end

  def after_authenticate(auth_token, existing_account: nil)
    if SiteSetting.resonite_oauth_debug_group_sync
      resonite_oauth_log_group_sync(
        "STEP 1 after_authenticate start uid=#{auth_token['uid'].inspect} existing_account_id=#{existing_account&.user_id.inspect}",
      )
    end

    result = super

    tag_sync = SiteSetting.resonite_oauth_groups_claim.present?
    supporter_sync = SiteSetting.resonite_oauth_active_supporter_group.present?

    if SiteSetting.resonite_oauth_debug_group_sync && !tag_sync && !supporter_sync
      resonite_oauth_log_group_sync(
        "STEP 2 sync bypassed: resonite_oauth_groups_claim and resonite_oauth_active_supporter_group are both blank.",
      )
      return result
    end

    return result if !tag_sync && !supporter_sync

    raw = auth_token.extra&.dig(:raw_info)
    matched = []
    claim = nil
    groups = nil
    supporter_appended = false

    if tag_sync
      claim = SiteSetting.resonite_oauth_groups_claim
      groups = raw.is_a?(Hash) ? (raw[claim] || raw[claim.to_sym]) : nil

      if groups.is_a?(Array)
        matched.concat(groups.map { |group_name| { id: group_name, name: group_name } })
      elsif groups.present?
        resonite_oauth_log("groups claim '#{claim}' is not an array: #{groups.class}", error: true)
      else
        resonite_oauth_log("groups claim '#{claim}' not found in auth token")
      end
    end

    matched_before_supporter = matched.size
    if supporter_sync && raw.is_a?(Hash) &&
         resonite_truthy?(raw["isActiveSupporter"] || raw[:isActiveSupporter])
      g = SiteSetting.resonite_oauth_active_supporter_group
      unless matched.any? { |e| e[:id] == g }
        matched << { id: g, name: g }
        supporter_appended = true
      end
    end

    if SiteSetting.resonite_oauth_debug_group_sync
      resonite_oauth_log_group_sync_debug(
        auth_token,
        result,
        tag_sync: tag_sync,
        supporter_sync: supporter_sync,
        raw: raw,
        claim: claim,
        groups: groups,
        matched: matched,
        supporter_appended: supporter_appended,
        matched_before_supporter: matched_before_supporter,
      )
    end

    result.associated_groups = matched
    resonite_oauth_log_group_sync(
      "STEP 3 result.associated_groups assigned count=#{matched.size}",
    ) if SiteSetting.resonite_oauth_debug_group_sync
    result
  end

  def always_update_user_email?
    SiteSetting.resonite_oauth_overrides_email
  end

  def match_by_email
    SiteSetting.resonite_oauth_match_by_email
  end

  def discovery_document_url
    SiteSetting.resonite_oauth_discovery_document_url.presence || DISCOVERY_DOCUMENT_DEFAULT
  end

  def discovery_document
    document_url = discovery_document_url

    from_cache = true
    result =
      Discourse
        .cache
        .fetch("resonite-oauth-discovery-#{document_url}", expires_in: 10.minutes) do
          from_cache = false
          resonite_oauth_log("Fetching discovery document from #{document_url}")
          connection =
            Faraday.new(request: { timeout: request_timeout_seconds }) do |c|
              c.use Faraday::Response::RaiseError
              c.adapter FinalDestination::FaradayAdapter
            end
          JSON.parse(connection.get(document_url).body)
        rescue Faraday::Error, JSON::ParserError => e
          resonite_oauth_log(
            "Fetching discovery document raised error #{e.class} #{e.message}",
            error: true,
          )
          nil
        end

    resonite_oauth_log("Discovery document loaded from cache") if from_cache
    resonite_oauth_log("Discovery document is\n\n#{result.to_yaml}")

    result
  end

  def resonite_oauth_log(message, error: false)
    if error
      Rails.logger.error("Resonite OAuth: #{message}")
    elsif SiteSetting.resonite_oauth_verbose_logging
      Rails.logger.warn("Resonite OAuth: #{message}")
    end
  end

  def resonite_oauth_log_group_sync(message)
    return if !SiteSetting.resonite_oauth_debug_group_sync

    Rails.logger.warn("Resonite OAuth [group_sync]: #{message}")
  end

  def register_middleware(omniauth)
    profile_connection =
      lambda do |builder|
        if SiteSetting.resonite_oauth_verbose_logging
          builder.response :logger, Rails.logger, { bodies: true, formatter: ResoniteOAuthFaradayFormatter }
        end
        builder.request :url_encoded
        builder.adapter FinalDestination::FaradayAdapter
      end

    omniauth.provider :resonite_open_id_connect,
                      name: :resonite,
                      error_handler:
                        lambda { |error, message|
                          handlers = SiteSetting.resonite_oauth_error_redirects.split("\n")
                          handlers.each do |row|
                            parts = row.split("|")
                            return parts[1] if message.include? parts[0]
                          end
                          nil
                        },
                      verbose_logger: lambda { |message| resonite_oauth_log(message) },
                      setup:
                        lambda { |env|
                          opts = env["omniauth.strategy"].options

                          opts.deep_merge!(
                            client_id: SiteSetting.resonite_oauth_client_id,
                            client_secret: SiteSetting.resonite_oauth_client_secret,
                            discovery_document: discovery_document,
                            scope: SiteSetting.resonite_oauth_authorize_scope,
                            token_params: {},
                            passthrough_authorize_options: [],
                            passthrough_token_options: [],
                            claims: nil,
                            pkce: SiteSetting.resonite_oauth_use_pkce,
                            pkce_options: {
                              code_verifier: -> { generate_code_verifier },
                              code_challenge: ->(code_verifier) do
                                generate_code_challenge(code_verifier)
                              end,
                              code_challenge_method: "S256",
                            },
                            profile_endpoint:
                              SiteSetting.resonite_oauth_profile_api_url.presence ||
                                "https://account.resonite.com/api/user/profile",
                            assets_base_url:
                              SiteSetting.resonite_oauth_assets_base_url.presence ||
                                "https://assets.resonite.com",
                            http_timeout: request_timeout_seconds,
                            profile_connection_build: profile_connection,
                          )

                          opts[:client_options][:connection_opts] = {
                            request: {
                              timeout: request_timeout_seconds,
                            },
                          }

                          opts[:client_options][:connection_build] = lambda do |builder|
                            if SiteSetting.resonite_oauth_verbose_logging
                              builder.response :logger,
                                               Rails.logger,
                                               { bodies: true, formatter: ResoniteOAuthFaradayFormatter }
                            end

                            builder.request :url_encoded
                            builder.adapter FinalDestination::FaradayAdapter
                          end
                        }
  end

  def generate_code_verifier
    Base64.urlsafe_encode64(OpenSSL::Random.random_bytes(32)).tr("=", "")
  end

  def generate_code_challenge(code_verifier)
    Base64.urlsafe_encode64(Digest::SHA256.digest(code_verifier)).tr("+/", "-_").tr("=", "")
  end

  def request_timeout_seconds
    GlobalSetting.resonite_oauth_request_timeout_seconds
  end

  private

  def resonite_oauth_truncate_for_log(value, max = 120)
    s = value.inspect
    s.length > max ? "#{s[0, max]}...(truncated)" : s
  end

  def resonite_oauth_log_group_sync_debug(
    auth_token,
    result,
    tag_sync:,
    supporter_sync:,
    raw:,
    claim:,
    groups:,
    matched:,
    supporter_appended:,
    matched_before_supporter:
  )
    return if !SiteSetting.resonite_oauth_debug_group_sync

    uid = auth_token["uid"]
    resonite_oauth_log_group_sync(
      "uid=#{uid.inspect} result.user_id=#{result.user&.id.inspect} result.authenticator_name=#{result.authenticator_name.inspect}",
    )
    resonite_oauth_log_group_sync(
      "provides_groups?=#{provides_groups?} tag_sync=#{tag_sync} supporter_sync=#{supporter_sync}",
    )

    if tag_sync
      raw_keys =
        if raw.is_a?(Hash)
          raw.keys.map(&:to_s).uniq.sort.join(",")
        else
          "(raw_info not a Hash: #{raw.class})"
        end
      resonite_oauth_log_group_sync("groups_claim=#{claim.inspect} raw_info_keys=[#{raw_keys}]")

      if groups.nil?
        resonite_oauth_log_group_sync("resolved claim: nil (missing or wrong key)")
      else
        resonite_oauth_log_group_sync(
          "resolved claim: class=#{groups.class.name} array_length=#{groups.is_a?(Array) ? groups.size : 'n/a'}",
        )
        if groups.is_a?(Array)
          groups.each_with_index do |entry, i|
            resonite_oauth_log_group_sync(
              "tag[#{i}] class=#{entry.class.name} value=#{resonite_oauth_truncate_for_log(entry)}",
            )
          end
        end
      end
    end

    if supporter_sync && raw.is_a?(Hash)
      raw_sup = raw["isActiveSupporter"] || raw[:isActiveSupporter]
      resonite_oauth_log_group_sync(
        "isActiveSupporter raw=#{raw_sup.inspect} supporter_row_appended=#{supporter_appended} matched_size_before_supporter_branch=#{matched_before_supporter}",
      )
    elsif supporter_sync
      resonite_oauth_log_group_sync("supporter_sync enabled but raw_info is not a Hash")
    end

    payload = matched.map { |h| h.stringify_keys }
    resonite_oauth_log_group_sync("associated_groups payload (string keys)=#{payload.inspect}")

    resonite_oauth_log_group_sync(
      "Discourse matches group links on provider_name resonite and provider_id equal to each id; the group external id must match exactly (case-sensitive).",
    )
  end

  def resonite_truthy?(value)
    return false if value.nil?

    value == true || (value.is_a?(String) && value.downcase == "true")
  end
end
