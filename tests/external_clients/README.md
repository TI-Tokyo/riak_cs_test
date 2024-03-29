# Riak CS external client tests

These tests are integrated into riak\_cs\_test. By design, they are
run against a single-node Riak CS setup from
tests/external\_client\_test.erl, with this command:

```
AWS_ACCESS_KEY_ID=8SFYPUPEUCS599HZG-X0 \
AWS_SECRET_ACCESS_KEY=kySUm9lCtsbAzjiAZtF3an1QrbbmaAFV0bYuTQ \
USER_ID=9337d19ad75800a10b171f4bf1e4eeeadfec3eb432a15f3a75d528ebf9d3921d \
CS_HTTP_PORT=15018 make
```
(Unique key and secret will be generated by the riak\_cs\_test harness
for each run.)

Hint: To run individual tests, insert `timer:sleep(999999999999)`
before
```
    case rtcs_dev:cmd({spawn_executable, os:find_executable("make")},
                      [{cd, "client_tests"}, {env, Env}, {args, Args}]) of
```

Rebuild and run `./rcst -t external_client_tests`. Wait until the harness sets
up the dev clusters and reaches the sleep. Copy the credentials
printed on the last line.  Then, in a new shell, do something like this:

```
you@localhost:/path/to/riak_cs_test/client_tests/python $ AWS_ACCESS_KEY_ID=8SFYPUPEUCS599HZG-X0 \
AWS_SECRET_ACCESS_KEY=kySUm9lCtsbAzjiAZtF3an1QrbbmaAFV0bYuTQ \
USER_ID=9337d19ad75800a10b171f4bf1e4eeeadfec3eb432a15f3a75d528ebf9d3921d \
CS_HTTP_PORT=15018  RCST_VERBOSE=1 python -m unittest boto_test_versioning
```
For python tests, setting `RCST_VERBOSE` to `1` will pretty-print some responses; a
greater value will enable debug boto3 logging to console.
