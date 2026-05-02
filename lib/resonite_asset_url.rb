# frozen_string_literal: true

module ResoniteAssetUrl
  module_function

  # https://wiki.resonite.com/API — resdb links use the hash as path on assets.resonite.com
  def icon_https_url(icon_url, assets_base: "https://assets.resonite.com")
    return if icon_url.nil? || icon_url.to_s.strip.empty?
    s = icon_url.to_s.strip
    hash = resdb_hash(s)
    return if hash.blank?
    base = assets_base.to_s.chomp("/")
    "#{base}/#{hash}"
  end

  def resdb_hash(icon_url)
    return unless icon_url.is_a?(String)
    return unless icon_url.start_with?("resdb:///")
    rest = icon_url.sub(%r{\Aresdb:///}, "")
    rest.split(".").first
  end
end
