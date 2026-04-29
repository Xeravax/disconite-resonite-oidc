# frozen_string_literal: true

require_relative "omniauth_open_id_connect"
require_relative "resonite_asset_url"

module OmniAuth
  module Strategies
    class ResoniteOpenIDConnect < OpenIDConnect
      option :profile_endpoint, "https://account.resonite.com/api/user/profile"
      option :assets_base_url, "https://assets.resonite.com"
      option :http_timeout, 10
      option :profile_connection_build, nil

      def id_token_info
        @id_token_info ||=
          begin
            decoded = ::JWT.decode(access_token["id_token"], nil, false).first
            verbose_log("Loaded JWT\n\n#{decoded.to_yaml}")
            ::JWT::Claims.verify_payload!(
              decoded,
              :exp,
              :nbf,
              iss: options[:client_options][:site],
              aud: options.client_id,
            )

            # Resonite often omits `nonce` in the id_token even when we send one (authorization code
            # exchange already binds the token to this client). Only verify when the claim is present.
            if decoded["nonce"].present?
              if decoded["nonce"] != session.delete("omniauth.nonce")
                raise NonceVerifyError.new "JWT nonce does not match"
              end
            else
              session.delete("omniauth.nonce")
            end

            verbose_log("Verified JWT\n\n#{decoded.to_yaml}")

            decoded
          end
      end

      def resonite_profile
        @resonite_profile ||=
          begin
            url = options[:profile_endpoint].to_s
            raise OmniAuth::OpenIDConnect::DiscoveryError.new("profile_endpoint is blank") if url.blank?

            verbose_log("Fetching Resonite profile from #{url}")
            connection = profile_faraday_connection
            body = connection.get(url) { |req| req.headers["Authorization"] = "Bearer #{access_token.token}" }.body
            parsed = JSON.parse(body)
            verbose_log("Resonite profile response\n\n#{parsed.to_yaml}")
            parsed
          rescue Faraday::Error, JSON::ParserError => e
            options.verbose_logger&.call("Resonite profile fetch failed: #{e.class} #{e.message}")
            raise e
          end
      end

      def resonite_merged_raw_info
        @resonite_merged_raw_info ||=
          begin
            profile = resonite_profile
            ui =
              if options.use_userinfo
                userinfo_response.stringify_keys
              else
                {}
              end

            ui.merge(
              "sub" => id_token_info["sub"],
              "email" => profile["email"],
              "name" => profile["username"],
              "preferred_username" => profile["username"],
              "email_verified" => profile["isVerified"],
              "picture" =>
                ResoniteAssetUrl.icon_https_url(
                  profile.dig("profile", "iconUrl"),
                  assets_base: options[:assets_base_url],
                ),
            )
          end
      end

      uid { id_token_info["sub"] }

      info do
        profile = resonite_profile
        prune!(
          name: profile["username"],
          email: profile["email"],
          nickname: profile["username"].presence || profile["normalizedUsername"],
          image:
            ResoniteAssetUrl.icon_https_url(
              profile.dig("profile", "iconUrl"),
              assets_base: options[:assets_base_url],
            ),
        )
      end

      extra do
        prune!(id_token: access_token["id_token"], raw_info: resonite_merged_raw_info)
      end

      private

      def profile_faraday_connection
        @profile_faraday_connection ||=
          Faraday.new(request: { timeout: options[:http_timeout] }) do |builder|
            if options[:profile_connection_build]
              options[:profile_connection_build].call(builder)
            else
              builder.request :url_encoded
              builder.adapter FinalDestination::FaradayAdapter
            end
          end
      end
    end
  end
end

OmniAuth.config.add_camelization "resonite_open_id_connect", "ResoniteOpenIDConnect"
