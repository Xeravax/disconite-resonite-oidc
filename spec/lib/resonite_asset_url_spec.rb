# frozen_string_literal: true

require_relative "../../lib/resonite_asset_url"

describe ResoniteAssetUrl do
  describe ".icon_https_url" do
    it "converts resdb webp to assets URL" do
      expect(
        described_class.icon_https_url("resdb:///abc123def456.webp"),
      ).to eq("https://assets.resonite.com/abc123def456")
    end

    it "uses custom assets base" do
      expect(
        described_class.icon_https_url(
          "resdb:///aaabbbcccddd.webp",
          assets_base: "https://cdn.example.com",
        ),
      ).to eq("https://cdn.example.com/aaabbbcccddd")
    end

    it "returns nil for blank" do
      expect(described_class.icon_https_url(nil)).to be_nil
      expect(described_class.icon_https_url("")).to be_nil
    end

    it "returns nil for non-resdb" do
      expect(described_class.icon_https_url("https://example.com/x.png")).to be_nil
    end
  end
end
