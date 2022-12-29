.PHONY: test-client test-clojure test-boto test-ceph test-erlang test-ruby test-php test-go

#test-client: test-clojure test-boto test-ceph test-erlang test-ruby test-php test-go
test-client: test-boto test-go test-ruby test-s3cmd

test-python:
	@cd python && ${MAKE} CS_HTTP_PORT=$(CS_HTTP_PORT) AWS_ACCESS_KEY_ID=$(AWS_ACCESS_KEY_ID) AWS_SECRET_ACCESS_KEY=$(AWS_SECRET_ACCESS_KEY)

test-boto:
	@cd python && ${MAKE} boto_tests

test-ceph:
	@cd python && ${MAKE} ceph_tests

test-ruby:
	@bundle config set --local path 'vendor'
	@bundle --gemfile ruby/Gemfile
	@cd ruby && bundle exec rake spec

test-php:
	@cd php && ${MAKE}

test-go:
	@cd go && ${MAKE}

test-s3cmd:
	@cd s3cmd && ${MAKE}

test-clojure:
	@command -v lein >/dev/null 2>&1 || { echo >&2 "I require lein but it's not installed. \
	Please read client_tests/clojure/clj-s3/README."; exit 1; }
	@cd clojure/clj-s3 && lein do deps, midje

