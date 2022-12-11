.PHONY: test

S3CMD_VSN = 2.3.0

all: test

test: check_s3cmd_version
	@python s3cmd_tests.py

check_s3cmd_version:
	@if [ "$$(s3cmd --version)" = "s3cmd version $(S3CMD_VSN)\n" ]; then \
	    echo "This test was written for s3cmd version $(S3CMD_VSN).  Earlier or later versions may report information retrieved from S3 in different form, possibly breaking the test."; \
	fi
