# frozen_string_literal: true

require "faraday/logging/formatter"

class ResoniteOAuthFaradayFormatter < Faraday::Logging::Formatter
  def request(env)
    warn <<~LOG
      Resonite OAuth debugging: request #{env.method.upcase} #{env.url}

      Headers: #{env.request_headers}

      Body: #{env[:body]}
    LOG
  end

  def response(env)
    warn <<~LOG
      Resonite OAuth debugging: response status #{env.status}

      From #{env.method.upcase} #{env.url}

      Headers: #{env.response_headers}

      Body: #{env[:body]}
    LOG
  end
end
