# frozen_string_literal: true

require_relative "../../lib/omniauth_resonite_open_id_connect"

describe ResoniteOAuthAuthenticator do
  let(:authenticator) { described_class.new }
  fab!(:user)
  let(:hash) do
    OmniAuth::AuthHash.new(
      provider: "resonite",
      uid: "123456789",
      info: {
        name: "John Doe",
        email: user.email,
      },
      extra: {
        raw_info: {
          email: user.email,
          name: "John Doe",
        },
      },
    )
  end

  context "when email_verified is not supplied" do
    it "matches the user" do
      result = authenticator.after_authenticate(hash)

      expect(result.user).to eq(user)
    end
  end

  context "when email_verified is true" do
    it "matches the user" do
      hash[:extra][:raw_info][:email_verified] = true
      result = authenticator.after_authenticate(hash)
      expect(result.user).to eq(user)
    end

    it "matches the user as a true string" do
      hash[:extra][:raw_info][:email_verified] = "true"
      result = authenticator.after_authenticate(hash)
      expect(result.user).to eq(user)
    end

    it "matches the user as a titlecase true string" do
      hash[:extra][:raw_info][:email_verified] = "True"
      result = authenticator.after_authenticate(hash)
      expect(result.user).to eq(user)
    end
  end

  context "when isVerified from Resonite profile is used" do
    it "matches when isVerified is true" do
      hash[:extra][:raw_info] = {
        "email" => user.email,
        "isVerified" => true,
      }
      result = authenticator.after_authenticate(hash)
      expect(result.user).to eq(user)
    end
  end

  context "when email_verified is false" do
    it "does not match the user" do
      hash[:extra][:raw_info][:email_verified] = false
      result = authenticator.after_authenticate(hash)
      expect(result.user).to eq(nil)
    end

    it "does not match the user as a false string" do
      hash[:extra][:raw_info][:email_verified] = "false"
      result = authenticator.after_authenticate(hash)
      expect(result.user).to eq(nil)
    end
  end

  context "when match_by_email is false" do
    it "does not match the user" do
      SiteSetting.resonite_oauth_match_by_email = false
      result = authenticator.after_authenticate(hash)
      expect(result.user).to eq(nil)
    end
  end

  it "does not sync groups" do
    expect(authenticator.provides_groups?).to eq(false)
  end

  describe "discovery document fetching" do
    let(:document_url) { ResoniteOAuthAuthenticator::DISCOVERY_DOCUMENT_DEFAULT }
    let(:document) do
      {
        issuer: "https://account.resonite.com/",
        authorization_endpoint: "https://account.resonite.com/authorize",
        token_endpoint: "https://account.resonite.com/token",
        userinfo_endpoint: "https://account.resonite.com/userinfo",
      }.to_json
    end
    after { Discourse.cache.delete("resonite-oauth-discovery-#{document_url}") }

    it "loads the document correctly" do
      stub_request(:get, document_url).to_return(body: document)
      expect(authenticator.discovery_document.keys).to contain_exactly(
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "userinfo_endpoint",
      )
    end

    it "uses custom discovery URL when set" do
      custom = "https://id.example.com/.well-known/openid-configuration"
      SiteSetting.resonite_oauth_discovery_document_url = custom
      Discourse.cache.delete("resonite-oauth-discovery-#{custom}")
      stub_request(:get, custom).to_return(body: document)
      expect(authenticator.discovery_document.keys).to include("issuer")
    end

    it "handles a non-200 response" do
      stub_request(:get, document_url).to_return(status: 404)
      expect(authenticator.discovery_document).to eq(nil)
    end

    it "handles a network error" do
      stub_request(:get, document_url).to_timeout
      expect(authenticator.discovery_document).to eq(nil)
    end

    it "handles invalid json" do
      stub_request(:get, document_url).to_return(body: "this is not the json you're looking for")
      expect(authenticator.discovery_document).to eq(nil)
    end

    it "caches a success response" do
      stub = stub_request(:get, document_url).to_return(body: document)
      expect(authenticator.discovery_document).not_to eq(nil)
      expect(authenticator.discovery_document).not_to eq(nil)
      expect(stub).to have_been_requested.once
    end

    it "caches a failed response" do
      stub = stub_request(:get, document_url).to_return(status: 404)
      expect(authenticator.discovery_document).to eq(nil)
      expect(authenticator.discovery_document).to eq(nil)
      expect(stub).to have_been_requested.once
    end
  end
end
