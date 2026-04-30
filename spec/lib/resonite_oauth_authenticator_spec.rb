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

    it "sets authenticator_name to resonite" do
      result = authenticator.after_authenticate(hash)
      expect(result.authenticator_name).to eq("resonite")
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

  describe "group syncing (Resonite tags)" do
    context "when resonite_oauth_groups_claim and active_supporter_group are blank" do
      before do
        SiteSetting.resonite_oauth_groups_claim = ""
        SiteSetting.resonite_oauth_active_supporter_group = ""
      end

      it "does not provide groups" do
        expect(authenticator.provides_groups?).to eq(false)
      end

      it "does not set associated_groups" do
        hash[:extra][:raw_info]["tags"] = %w[mentor translator]
        result = authenticator.after_authenticate(hash)
        expect(result.associated_groups).to be_nil
      end
    end

    context "when resonite_oauth_groups_claim is tags" do
      before do
        SiteSetting.resonite_oauth_groups_claim = "tags"
        SiteSetting.resonite_oauth_active_supporter_group = ""
      end

      it "provides groups" do
        expect(authenticator.provides_groups?).to eq(true)
      end

      it "maps tags to associated_groups" do
        hash[:extra][:raw_info]["tags"] = %w[mentor translator]
        result = authenticator.after_authenticate(hash)
        expect(result.associated_groups).to eq(
          [{ id: "mentor", name: "mentor" }, { id: "translator", name: "translator" }],
        )
      end

      it "reapplies GroupUser membership on login for existing users" do
        group_name = "resonite-mentor-sync"
        group = Fabricate(:group, name: group_name)
        associated_group =
          AssociatedGroup.find_or_create_by!(
            provider_name: "resonite",
            provider_id: group_name,
          ) do |ag|
            ag.name = group_name
            ag.last_used = Time.zone.now
          end
        GroupAssociatedGroup.find_or_create_by!(group: group, associated_group: associated_group)
        GroupUser.where(user_id: user.id, group_id: group.id).delete_all

        hash[:extra][:raw_info]["tags"] = [group_name]
        result = authenticator.after_authenticate(hash)

        expect(result.user).to eq(user)
        expect(GroupUser.exists?(user_id: user.id, group_id: group.id)).to eq(true)
      end

      it "handles custom badge style tag strings" do
        hash[:extra][:raw_info]["tags"] = ["mentor", "custom badge:3f2b433508e038e3278f09eb3c3d6b4bb7c190da222b5c50500279a440a9575f"]
        result = authenticator.after_authenticate(hash)
        expect(result.associated_groups).to eq(
          [
            { id: "mentor", name: "mentor" },
            {
              id: "custom badge:3f2b433508e038e3278f09eb3c3d6b4bb7c190da222b5c50500279a440a9575f",
              name: "custom badge:3f2b433508e038e3278f09eb3c3d6b4bb7c190da222b5c50500279a440a9575f",
            },
          ],
        )
      end

      it "handles an empty tags array" do
        hash[:extra][:raw_info]["tags"] = []
        result = authenticator.after_authenticate(hash)
        expect(result.associated_groups).to eq([])
      end

      it "sets associated_groups to empty when the claim is missing" do
        result = authenticator.after_authenticate(hash)
        expect(result.associated_groups).to eq([])
      end

      it "logs an error when the claim is not an array" do
        hash[:extra][:raw_info]["tags"] = "not_an_array"
        Rails.logger.expects(:error).with(includes("not an array"))
        result = authenticator.after_authenticate(hash)
        expect(result.associated_groups).to eq([])
      end
    end

    describe "active supporter group" do
      before do
        SiteSetting.resonite_oauth_groups_claim = ""
        SiteSetting.resonite_oauth_active_supporter_group = "resonite-supporters"
      end

      it "provides groups when only supporter group is configured" do
        expect(authenticator.provides_groups?).to eq(true)
      end

      it "adds the supporter group when isActiveSupporter is true" do
        hash[:extra][:raw_info]["isActiveSupporter"] = true
        result = authenticator.after_authenticate(hash)
        expect(result.associated_groups).to eq(
          [{ id: "resonite-supporters", name: "resonite-supporters" }],
        )
      end

      it "accepts string true for isActiveSupporter" do
        hash[:extra][:raw_info]["isActiveSupporter"] = "true"
        result = authenticator.after_authenticate(hash)
        expect(result.associated_groups).to eq(
          [{ id: "resonite-supporters", name: "resonite-supporters" }],
        )
      end

      it "does not add the group when isActiveSupporter is false" do
        hash[:extra][:raw_info]["isActiveSupporter"] = false
        result = authenticator.after_authenticate(hash)
        expect(result.associated_groups).to eq([])
      end

      it "merges supporter group with tags when both are configured" do
        SiteSetting.resonite_oauth_groups_claim = "tags"
        hash[:extra][:raw_info]["tags"] = ["mentor"]
        hash[:extra][:raw_info]["isActiveSupporter"] = true
        result = authenticator.after_authenticate(hash)
        expect(result.associated_groups).to eq(
          [
            { id: "mentor", name: "mentor" },
            { id: "resonite-supporters", name: "resonite-supporters" },
          ],
        )
      end

      it "does not duplicate if a tag matches the supporter group name" do
        SiteSetting.resonite_oauth_groups_claim = "tags"
        hash[:extra][:raw_info]["tags"] = %w[mentor resonite-supporters]
        hash[:extra][:raw_info]["isActiveSupporter"] = true
        result = authenticator.after_authenticate(hash)
        expect(result.associated_groups).to eq(
          [
            { id: "mentor", name: "mentor" },
            { id: "resonite-supporters", name: "resonite-supporters" },
          ],
        )
      end
    end

    describe "resonite_oauth_debug_group_sync" do
      before do
        SiteSetting.resonite_oauth_groups_claim = "tags"
        SiteSetting.resonite_oauth_active_supporter_group = ""
      end

      it "logs [group_sync] lines when enabled" do
        SiteSetting.resonite_oauth_debug_group_sync = true
        hash[:extra][:raw_info]["tags"] = %w[mentor]
        Rails.logger.expects(:warn).with(includes("[group_sync]")).at_least_once
        authenticator.after_authenticate(hash)
      end

      it "logs when both sync settings are blank and debug is enabled" do
        SiteSetting.resonite_oauth_debug_group_sync = true
        SiteSetting.resonite_oauth_groups_claim = ""
        SiteSetting.resonite_oauth_active_supporter_group = ""
        Rails.logger.expects(:warn).with(includes("STEP 2 sync bypassed")).once
        authenticator.after_authenticate(hash)
      end
    end
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
