.PHONY: test all clean
.DEFAULT: all

all: test

phpunit:
	@composer update

test: phpunit
	@phpunit

clean:
	@rm -rf composer.lock vendor phpunit
