.PHONY: test all
.DEFAULT: all

all: test

test:
	@python boto_test.py

test-auth-v2: $(DEPS)
	@env CS_AUTH=auth-v2 python boto_test.py
