.PHONY: distclean compile clean quickbuild

REBAR=./rebar3

all: compile
	@$(REBAR) as test compile
	@$(REBAR) escriptize
	@SMOKE_TEST=1 $(REBAR) escriptize
	@mkdir -p ./ebin
	@cp ./_build/test/lib/riak_test/tests/*.beam ./ebin

docsclean:
	@rm -rf doc/*.png doc/*.html doc/*.css edoc-info

compile:
	@$(REBAR) compile

clean:
	@$(REBAR) clean

distclean:
	@$(REBAR) clean -a
	@rm -rf riak_test _build

quickbuild:
	@$(REBAR) compile
	@$(REBAR) escriptize
