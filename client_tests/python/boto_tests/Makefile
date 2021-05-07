.PHONY: test test-auth-v2 test-auth-v4 clean all
.DEFAULT: all

DEPS = env/lib/python3.8/site-packages
BIN = env/bin

all: test

env:
	@virtualenv env

$(DEPS) $(BIN): requirements.txt env
	@env/bin/pip install -r requirements.txt
	rm -f $(DEPS)/boto/auth.pyc

test: test-auth-v2 test-auth-v4

test-auth-v2: $(DEPS) $(BIN)
	env CS_AUTH=auth-v2 env/bin/python boto_test.py

test-auth-v4: $(DEPS) $(BIN)
	env CS_AUTH=auth-v4 env/bin/python boto_test.py

clean:
	@rm -rf env
