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
    result = super
    # Auth::Result#apply_associated_attributes! resolves the authenticator by name.
    # Ensure this is present so group-sync application is not skipped.
    result.authenticator_name ||= name

    tag_sync = SiteSetting.resonite_oauth_groups_claim.present?
    supporter_sync = SiteSetting.resonite_oauth_active_supporter_group.present?

    return result if !tag_sync && !supporter_sync

    raw = auth_token.extra&.dig(:raw_info)
    matched = []

    if tag_sync
      claim = SiteSetting.resonite_oauth_groups_claim
      groups = nil
      groups = raw.is_a?(Hash) ? (raw[claim] || raw[claim.to_sym]) : nil

      if groups.is_a?(Array)
        matched.concat(groups.map { |group_name| { id: group_name, name: group_name } })
      elsif groups.present?
        resonite_oauth_log("groups claim '#{claim}' is not an array: #{groups.class}", error: true)
      else
        resonite_oauth_log("groups claim '#{claim}' not found in auth token")
      end
    end

    if supporter_sync && raw.is_a?(Hash) &&
         resonite_truthy?(raw["isActiveSupporter"] || raw[:isActiveSupporter])
      g = SiteSetting.resonite_oauth_active_supporter_group
      unless matched.any? { |e| e[:id] == g }
        matched << { id: g, name: g }
      end
    end

    result.associated_groups = matched
    ensure_group_membership_from_associated_groups(result.user, matched)
    result
  end

  def after_create_account(user, auth_result)
    super
    ensure_group_membership_from_associated_groups(user, auth_result.associated_groups)
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

  def resonite_truthy?(value)
    return false if value.nil?

    value == true || (value.is_a?(String) && value.downcase == "true")
  end

  def ensure_group_membership_from_associated_groups(user, associated_groups)
    return if user.blank? || associated_groups.blank?

    associated_groups.each do |entry|
      group_id = entry[:id] || entry["id"]
      group_name = entry[:name] || entry["name"]
      next if group_id.blank? || group_name.blank?

      associated_group =
        begin
          AssociatedGroup.find_or_create_by(
            name: group_name,
            provider_id: group_id,
            provider_name: name,
          )
        rescue ActiveRecord::RecordNotUnique
          retry
        end

      associated_group.groups.each do |group|
        group.add_automatically(user, subject: associated_group.label)
      end
    end

  end
end
