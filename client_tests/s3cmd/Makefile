.PHONY: test clean all
.DEFAULT: all

DEPS = env/lib/python3.10/site-packages
BIN = env/bin

all: test

env:
	@virtualenv env

$(DEPS) $(BIN): requirements.txt env
	@env/bin/pip install -r requirements.txt
	rm -f $(DEPS)/boto/auth.pyc

test: $(DEPS) check_s3cmd_version
	env env/bin/python s3cmd_tests.py

check_s3cmd_version:
	@if [ "$$(s3cmd --version)" = "s3cmd version 2.2.0\n" ]; then \
	    echo "This test was written for s3cmd version 2.2.0.  Earlier or later versions may report information retrieved from S3 in different form, possibly breaking the test."; \
	fi
clean:
	@rm -rf env
