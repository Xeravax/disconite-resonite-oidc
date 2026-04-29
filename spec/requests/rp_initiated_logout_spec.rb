# frozen_string_literal: true

describe "Resonite OAuth RP-initiated logout" do
  let(:document_url) { ResoniteOAuthAuthenticator::DISCOVERY_DOCUMENT_DEFAULT }
  let(:document) do
    {
      issuer: "https://account.resonite.com/",
      authorization_endpoint: "https://account.resonite.com/authorize",
      token_endpoint: "https://account.resonite.com/token",
      userinfo_endpoint: "https://account.resonite.com/userinfo",
      end_session_endpoint: "https://account.resonite.com/endsession",
    }
  end
  fab!(:user)

  before do
    SiteSetting.resonite_oauth_enabled = true
    SiteSetting.resonite_oauth_rp_initiated_logout = true
    stub_request(:get, document_url).to_return(body: lambda { |_r| document.to_json })
  end

  after { Discourse.cache.delete("resonite-oauth-discovery-#{document_url}") }

  it "does nothing for a user with no resonite record" do
    sign_in(user)
    delete "/session/#{user.username}", xhr: true
    expect(response.status).to eq(200)
    expect(response.parsed_body["redirect_url"]).to eq("/")
  end

  it "does nothing for a user with no token in their resonite record" do
    sign_in(user)
    UserAssociatedAccount.create!(provider_name: "resonite", user: user, provider_uid: "myuid")
    delete "/session/#{user.username}", xhr: true
    expect(response.status).to eq(200)
    expect(response.parsed_body["redirect_url"]).to eq("/")
  end

  context "with user and token" do
    before do
      sign_in(user)
      UserAssociatedAccount.create!(
        provider_name: "resonite",
        user: user,
        provider_uid: "myuid",
        extra: {
          id_token: "myoidctoken",
        },
      )
    end

    it "redirects the user to the logout endpoint" do
      delete "/session/#{user.username}", xhr: true
      expect(response.status).to eq(200)
      expect(response.parsed_body["redirect_url"]).to eq(
        "https://account.resonite.com/endsession?id_token_hint=myoidctoken",
      )
    end

    it "correctly handles logout urls with existing query params" do
      document[:end_session_endpoint] += "?param=true"

      delete "/session/#{user.username}", xhr: true
      expect(response.status).to eq(200)
      expect(response.parsed_body["redirect_url"]).to eq(
        "https://account.resonite.com/endsession?param=true&id_token_hint=myoidctoken",
      )
    end

    it "includes the redirect URI if set" do
      SiteSetting.resonite_oauth_rp_initiated_logout_redirect = "https://example.com"
      delete "/session/#{user.username}", xhr: true
      expect(response.status).to eq(200)
      expect(response.parsed_body["redirect_url"]).to eq(
        "https://account.resonite.com/endsession?id_token_hint=myoidctoken&post_logout_redirect_uri=https%3A%2F%2Fexample.com",
      )
    end

    it "does not redirect if plugin disabled" do
      SiteSetting.resonite_oauth_enabled = false
      delete "/session/#{user.username}", xhr: true
      expect(response.status).to eq(200)
      expect(response.parsed_body["redirect_url"]).to eq("/")
    end

    it "does not redirect if rp initiated logout disabled" do
      SiteSetting.resonite_oauth_rp_initiated_logout = false
      delete "/session/#{user.username}", xhr: true
      expect(response.status).to eq(200)
      expect(response.parsed_body["redirect_url"]).to eq("/")
    end

    it "does not redirect if the discovery document is missing the endpoint" do
      stub_request(:get, document_url).to_return(body: "{}")
      delete "/session/#{user.username}", xhr: true
      expect(response.status).to eq(200)
      expect(response.parsed_body["redirect_url"]).to eq("/")
    end

    it "does not redirect if the discovery document has a network error" do
      stub_request(:get, document_url).to_timeout
      delete "/session/#{user.username}", xhr: true
      expect(response.status).to eq(200)
      expect(response.parsed_body["redirect_url"]).to eq("/")
    end

    context "with client_id included in logout endpoint" do
      before do
        SiteSetting.resonite_oauth_client_id = "test-client-id"
        SiteSetting.resonite_oauth_rp_initiated_logout_include_client_id = true
      end

      it "appends the client id to the logout endpoint url" do
        delete "/session/#{user.username}", xhr: true
        expect(response.status).to eq(200)
        expect(response.parsed_body["redirect_url"]).to eq(
          "https://account.resonite.com/endsession?id_token_hint=myoidctoken&client_id=test-client-id",
        )
      end
    end
  end
end
