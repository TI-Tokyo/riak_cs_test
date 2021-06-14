.PHONY: test clean all
.DEFAULT: all

DEPS = env/lib/python3.8/site-packages
BIN = env/bin

all: test

env:
	@virtualenv env

$(DEPS) $(BIN): requirements.txt env
	@env/bin/pip install -r requirements.txt
	rm -f $(DEPS)/boto/auth.pyc

test: $(DEPS)
	env env/bin/python boto_test.py

test-auth-v2: $(DEPS)
	env CS_AUTH=auth-v2 env/bin/python boto_test.py

clean:
	@rm -rf env
