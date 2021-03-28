HEAD_REVISION   ?= $(shell git describe --tags --exact-match HEAD 2>/dev/null)

.PHONY: deps

APPS = kernel stdlib sasl erts ssl tools os_mon runtime_tools crypto inets \
	xmerl webtool eunit syntax_tools compiler hipe mnesia public_key \
	observer wx gs
PLT = $(HOME)/.riak-test_dialyzer_plt

REBAR=./rebar3

all: deps compile
	$(REBAR) as test compile
	$(REBAR) escriptize
	SMOKE_TEST=1 $(REBAR) escriptize
	mkdir -p ./ebin
	cp ./_build/test/lib/riak_test/tests/*.beam ./ebin

deps:
	$(if $(HEAD_REVISION),$(warning "Warning: you have checked out a tag ($(HEAD_REVISION)) and should use the locked-deps target"))
	$(REBAR) get-deps

docsclean:
	@rm -rf doc/*.png doc/*.html doc/*.css edoc-info

compile: deps
	$(REBAR) compile

clean:
	@$(REBAR) clean

distclean: clean
	@rm -rf riak_test _build

quickbuild:
	$(REBAR) compile
	$(REBAR) escriptize

## KLUDGE, as downgrade script is not included in the release.
src/rtcs/downgrade_bitcask.erl:
	@wget --no-check-certificate https://raw.githubusercontent.com/basho/bitcask/develop/priv/scripts/downgrade_bitcask.erl \
		-O riak_test/src/downgrade_bitcask.erl

##################
# Dialyzer targets
##################

# include tools.mk
