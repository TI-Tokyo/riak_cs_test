-module(external_client_tests).

-export([confirm/0]).

-include_lib("erlcloud/include/erlcloud_aws.hrl").
-include_lib("eunit/include/eunit.hrl").

-define(EXTRA_TEST_BUCKET, "go-test-bucket").

confirm() ->
    application:ensure_all_started(ibrowse),
    {{UserConfig, AdminUserId}, {RiakNodes, _CSNodes}} =
        rtcs:setup(1, [{cs, cs_config()}]),

    CsPortStr = integer_to_list(rtcs_config:cs_port(hd(RiakNodes))),

    Cmd = os:find_executable("make"),
    Args = ["test-client"],
    Env = [{"CS_HTTP_PORT",          CsPortStr},
           {"AWS_ACCESS_KEY_ID",     UserConfig#aws_config.access_key_id},
           {"AWS_SECRET_ACCESS_KEY", UserConfig#aws_config.secret_access_key},
           {"USER_ID",               AdminUserId}],

    ?assertEqual(ok, erlcloud_s3:create_bucket(?EXTRA_TEST_BUCKET, UserConfig)),

    WaitTime = 5 * rt_config:get(rt_max_wait_time),
    case rtcs_exec:cmd(Cmd, [{cd, "client_tests"}, {env, Env}, {args, Args}], WaitTime) of
        ok ->
            pass;
        {error, Reason} ->
            logger:error("Error : ~p", [Reason]),
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
