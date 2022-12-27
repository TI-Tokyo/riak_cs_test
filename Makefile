.PHONY: distclean compile clean

REBAR ?= ./rebar3

all:
	@$(REBAR) as test compile
	@$(REBAR) escriptize
	@mkdir -p ./ebin
	@cp ./_build/test/lib/riak_test/tests/*.beam ./ebin

compile:
	@$(REBAR) as test compile

clean:
	@$(REBAR) clean

distclean:
	@$(REBAR) clean -a
	@rm -rf riak_test _build
