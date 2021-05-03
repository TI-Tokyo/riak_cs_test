-module(external_client_tests).

-export([confirm/0]).

-include_lib("erlcloud/include/erlcloud_aws.hrl").

-define(TEST_BUCKET, "external-client-test").

confirm() ->
    {UserConfig, {RiakNodes, _CSNodes, _Stanchion}} = rtcs:setup(2, [{cs, cs_config()}]),
    ok = erlcloud_s3:create_bucket("external-client-test", UserConfig),
    CsPortStr = integer_to_list(rtcs_config:cs_port(hd(RiakNodes))),

    Cmd = os:find_executable("make"),
    Args = ["-k", "test-client"],
    Env = [{"CS_HTTP_PORT",          CsPortStr},
           {"AWS_ACCESS_KEY_ID",     UserConfig#aws_config.access_key_id},
           {"AWS_SECRET_ACCESS_KEY", UserConfig#aws_config.secret_access_key},
           {"CS_BUCKET",             ?TEST_BUCKET}],
    WaitTime = 5 * rt_config:get(rt_max_wait_time),
    case rtcs_exec:cmd(Cmd, [{cd, "client_tests"}, {env, Env}, {args, Args}], WaitTime) of
        ok ->
            rtcs_dev:pass();
        {error, Reason} ->
            lager:error("Error : ~p", [Reason]),
            error({external_client_tests, Reason})
    end.

cs_config() ->
    [{riak_cs,
      [{connection_pools, [{request_pool, {32, 0}}]},
       {enforce_multipart_part_size, false},
       {max_buckets_per_user, 300},
       {auth_v4_enabled, true}
      ]
     }].
