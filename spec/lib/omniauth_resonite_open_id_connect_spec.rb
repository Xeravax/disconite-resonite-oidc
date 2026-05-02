# frozen_string_literal: true

require_relative "../../lib/omniauth_resonite_open_id_connect"

describe OmniAuth::Strategies::ResoniteOpenIDConnect do
  let(:app) { ->(*_args) { [200, {}, ["Hello."]] } }

  let(:discovery_document) do
    {
      "issuer" => "https://account.resonite.com/",
      "authorization_endpoint" => "https://account.resonite.com/authorize",
      "token_endpoint" => "https://account.resonite.com/token",
      "userinfo_endpoint" => "https://account.resonite.com/userinfo",
    }
  end

  let(:strategy) do
    OmniAuth::Strategies::ResoniteOpenIDConnect.new(
      app,
      "appid",
      "secret",
      discovery_document: discovery_document,
      profile_endpoint: "https://account.resonite.com/api/user/profile",
      assets_base_url: "https://assets.resonite.com",
    )
  end

  before { OmniAuth.config.test_mode = true }

  after { OmniAuth.config.test_mode = false }

  def stub_callback_request!(strategy)
    strategy.stubs(:full_host).returns("https://example.com")
    req = mock("request")
    strategy.stubs(:request).returns(req)
    req.stubs(:params).returns({})
    auth = strategy.authorize_params
    req.stubs(:params).returns("state" => auth[:state], "code" => "supersecretcode")
    auth
  end

  context "with discovery loaded" do
    before do
      strategy.stubs(:request).returns(mock("object"))
      strategy.request.stubs(:params).returns({})
      strategy.discover!
    end

    context "without id_token nonce (Resonite)" do
      before do
        strategy.stubs(:request).returns(mock("object"))
        strategy.request.stubs(:params).returns({})
        strategy.discover!
        stub_callback_request!(strategy)
        id_token_jwt =
          ::JWT.encode(
            {
              iss: "https://account.resonite.com/",
              sub: "U-testuser",
              aud: "appid",
              iat: Time.now.to_i - 30,
              exp: Time.now.to_i + 120,
            },
            nil,
            "none",
          )

        stub_request(:post, "https://account.resonite.com/token").to_return do |_req|
          {
            status: 200,
            body: {
              access_token: "AnAccessToken",
              expires_in: 3600,
              id_token: id_token_jwt,
            }.to_json,
            headers: {
              "Content-Type" => "application/json",
            },
          }
        end

        stub_request(:get, "https://account.resonite.com/userinfo").to_return(
          status: 200,
          body: {
            "sub" => "U-testuser",
            "iss" => "https://account.resonite.com/",
            "aud" => "appid",
          }.to_json,
          headers: {
            "Content-Type" => "application/json",
          },
        )

        stub_request(:get, "https://account.resonite.com/api/user/profile").to_return(
          status: 200,
          body: {
            "id" => "U-testuser",
            "username" => "ResoUser",
            "email" => "reso@example.com",
            "isVerified" => true,
            "profile" => {
              "iconUrl" => "resdb:///abc123def456.webp",
            },
          }.to_json,
          headers: {
            "Content-Type" => "application/json",
          },
        )
      end

      it "accepts id_token and loads profile" do
        expect(strategy.callback_phase[0]).to eq(200)
        expect(strategy.uid).to eq("U-testuser")
        expect(strategy.info[:name]).to eq("ResoUser")
        expect(strategy.info[:email]).to eq("reso@example.com")
        expect(strategy.info[:image]).to eq("https://assets.resonite.com/abc123def456")
        expect(strategy.extra[:raw_info]["email_verified"]).to eq(true)
      end
    end

    context "with id_token nonce" do
      let!(:auth) do
        strategy.stubs(:request).returns(mock("object"))
        strategy.request.stubs(:params).returns({})
        strategy.discover!
        stub_callback_request!(strategy)
      end

      let(:id_token_jwt) do
        ::JWT.encode(
          {
            iss: "https://account.resonite.com/",
            sub: "U-testuser",
            aud: "appid",
            iat: Time.now.to_i - 30,
            exp: Time.now.to_i + 120,
            nonce: auth[:nonce],
          },
          nil,
          "none",
        )
      end

      before do
        stub_request(:post, "https://account.resonite.com/token").to_return do |_req|
          {
            status: 200,
            body: {
              access_token: "AnAccessToken",
              expires_in: 3600,
              id_token: id_token_jwt,
            }.to_json,
            headers: {
              "Content-Type" => "application/json",
            },
          }
        end

        stub_request(:get, "https://account.resonite.com/userinfo").to_return(
          status: 200,
          body: { "sub" => "U-testuser" }.to_json,
          headers: {
            "Content-Type" => "application/json",
          },
        )

        stub_request(:get, "https://account.resonite.com/api/user/profile").to_return(
          status: 200,
          body: {
            "username" => "U",
            "email" => "u@example.com",
            "isVerified" => true,
          }.to_json,
          headers: {
            "Content-Type" => "application/json",
          },
        )
      end

      it "verifies nonce when present" do
        expect(strategy.callback_phase[0]).to eq(200)
        expect(strategy.uid).to eq("U-testuser")
      end

      it "rejects wrong nonce when present" do
        strategy.session["omniauth.nonce"] = "wrong"
        expect(strategy.callback_phase[0]).to eq(302)
      end
    end
  end
end
