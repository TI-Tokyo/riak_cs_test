require 'json'
require 'uuid'
require 'tempfile'

def s3_conf
  {
    http_proxy: cs_uri,
    endpoint: cs_uri,
    http_read_timeout: 2000
  }
end

def cs_uri
  "http://127.0.0.1:#{cs_port}"
end

def cs_port
  ENV['CS_HTTP_PORT'] || 15018
end
