%% ---------------------------------------------------------------------
%%
%% Copyright (c) 2007-2016 Basho Technologies, Inc.
%%               2021-2023 TI Tokyo    All Rights Reserved.
%%
%% This file is provided to you under the Apache License,
%% Version 2.0 (the "License"); you may not use this file
%% except in compliance with the License.  You may obtain
%% a copy of the License at
%%
%%   http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing,
%% software distributed under the License is distributed on an
%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%% KIND, either express or implied.  See the License for the
%% specific language governing permissions and limitations
%% under the License.
%%
%% ---------------------------------------------------------------------

-module(regression_tests).

%% @doc this module gathers various regression tests which can be
%% separate easily. Regression tests which needs configuration change
%% can be written as different module. In case of rtcs:setup(1) with
%% vanilla CS setup used. Otherwise feel free to create an independent
%% module like cs743_regression_test.

-export([confirm/0]).

-include_lib("xmerl/include/xmerl.hrl").
-include_lib("eunit/include/eunit.hrl").
-include_lib("erlcloud/include/erlcloud_aws.hrl").
-include("riak_cs.hrl").

-define(TEST_BUCKET_CS347, "test-bucket-cs347").

-define(assert500(X),
        ?assertError({aws_error, {http_error, 500, _, _}}, (X))).
-define(assertProp(Key, Expected, Props),
        ?assertEqual(Expected,
                     proplists:get_value(Key, Props))).

-define(assertHasBucket(B, UserConfig),
        ?assert(
           lists:any(
             fun(PL) -> proplists:get_value(name, PL) == B end,
             proplists:get_value(buckets, erlcloud_s3:list_buckets(UserConfig)))
          )
       ).
-define(assertNoBuckets(UserConfig),
        ?assertEqual([], proplists:get_value(buckets, erlcloud_s3:list_buckets(UserConfig)))).

confirm() ->
    %% Setting short timeouts to accelarate verify_cs756
    SetupInfo = {{UserConfig, _}, _Nodes} = rtcs:setup(1, [{cs, [{riak_cs, [{riakc_timeouts, 1000}]}]}]),

    ok = verify_cs296(SetupInfo, "test-bucket-cs296"),
    ok = verify_cs347(SetupInfo, "test-bucket-cs347"),
    ok = verify_cs436(SetupInfo, "test-bucket-cs436"),
    ok = verify_cs512(UserConfig, "test-bucket-cs512"),
    ok = verify_cs770(SetupInfo, "test-bucket-cs770"),
    %% Append your next regression tests here

    %% regression of CS#756 must be the last test as it stops all Riak
    %% nodes.
    ok = verify_cs756(SetupInfo, "test-bucket-cs756"),

    pass.

%% @doc Regression test for `riak_cs' <a href="https://github.com/basho/riak_cs/issues/296">
%% issue 296</a>. The issue description is: 403 instead of 404 returned when
%% trying to list nonexistent bucket.
verify_cs296(_SetupInfo = {{UserConfig, _}, {_RiakNodes, _CSNodes}}, BucketName) ->
    logger:info("CS296: User is valid on the cluster, and has no buckets"),
    ?assertNoBuckets(UserConfig),

    ?assertError({aws_error, {http_error, 404, _, _}}, erlcloud_s3:list_objects(BucketName, UserConfig)),

    logger:info("creating bucket ~p", [BucketName]),
    ?assertEqual(ok, erlcloud_s3:create_bucket(BucketName, UserConfig)),

    ?assertHasBucket(BucketName, UserConfig),

    logger:info("deleting bucket ~p", [BucketName]),
    ?assertEqual(ok, erlcloud_s3:delete_bucket(BucketName, UserConfig)),

    ?assertError({aws_error, {http_error, 404, _, _}}, erlcloud_s3:list_objects(BucketName, UserConfig)),
    ok.

%% @doc Regression test for `riak_cs' <a href="https://github.com/basho/riak_cs/issues/347">
%% issue 347</a>. The issue description is: No response body in 404 to the
%% bucket that have never been created once.
verify_cs347(_SetupInfo = {{UserConfig, _}, {_RiakNodes, _CSNodes}}, BucketName) ->

    logger:info("CS347: User is valid on the cluster, and has no buckets"),
    ?assertNoBuckets(UserConfig),

    ListObjectRes1 =
        case catch erlcloud_s3:list_objects(BucketName, UserConfig) of
            {'EXIT', {{aws_error, Error}, _}} ->
                Error;
            Result ->
                Result
        end,
    ?assert(check_no_such_bucket(ListObjectRes1, "/" ++ ?TEST_BUCKET_CS347 ++ "/")),

    logger:info("creating bucket ~p", [BucketName]),
    ?assertEqual(ok, erlcloud_s3:create_bucket(BucketName, UserConfig)),

    ?assertHasBucket(BucketName, UserConfig),

    logger:info("deleting bucket ~p", [BucketName]),
    ?assertEqual(ok, erlcloud_s3:delete_bucket(BucketName, UserConfig)),

    ListObjectRes2 =
        case catch erlcloud_s3:list_objects(BucketName, UserConfig) of
            {'EXIT', {{aws_error, Error2}, _}} ->
                Error2;
            Result2 ->
                Result2
        end,
    ?assert(check_no_such_bucket(ListObjectRes2, "/" ++ ?TEST_BUCKET_CS347 ++ "/")),
    ok.

check_no_such_bucket(Response, Resource) ->
    check_error_response(Response,
                         404,
                         "NoSuchBucket",
                         "The specified bucket does not exist.",
                         Resource).

check_error_response({_, Status, _, RespStr} = _Response,
                     Status,
                     Code, Message, Resource) ->
    {RespXml, _} = xmerl_scan:string(binary_to_list(RespStr)),
    lists:all(error_child_element_verifier(Code, Message, Resource),
              RespXml#xmlElement.content).

error_child_element_verifier(Code, Message, Resource) ->
    fun(#xmlElement{name='Code', content=[Content]}) ->
            Content#xmlText.value =:= Code;
       (#xmlElement{name='Message', content=[Content]}) ->
            Content#xmlText.value =:= Message;
       (#xmlElement{name='Resource', content=[Content]}) ->
            Content#xmlText.value =:= Resource;
       (_) ->
            true
    end.


%% @doc Regression test for `riak_cs' <a href="https://github.com/basho/riak_cs/issues/436">
%% issue 436</a>. The issue description is: A 500 is returned instead of a 404 when
%% trying to put to a nonexistent bucket.
verify_cs436(_SetupInfo = {{UserConfig, _}, {_RiakNodes, _CSNodes}}, BucketName) ->
    logger:info("CS436: User is valid on the cluster, and has no buckets"),
    ?assertEqual([], proplists:get_value(buckets, erlcloud_s3:list_buckets(UserConfig))),

    ?assertError({aws_error, {http_error, 404, _, _}},
                 erlcloud_s3:put_object(BucketName,
                                        "somekey",
                                        crypto:strong_rand_bytes(100),
                                        UserConfig)),

    %% Create and delete test bucket
    logger:info("creating bucket ~p", [BucketName]),
    ?assertEqual(ok, erlcloud_s3:create_bucket(BucketName, UserConfig)),

    ?assertHasBucket(BucketName, UserConfig),

    logger:info("deleting bucket ~p", [BucketName]),
    ?assertEqual(ok, erlcloud_s3:delete_bucket(BucketName, UserConfig)),

    ?assertNoBuckets(UserConfig),

    %% Attempt to put object again and ensure result is still 404
    ?assertError({aws_error, {http_error, 404, _, _}},
                 erlcloud_s3:put_object(BucketName,
                                        "somekey",
                                        crypto:strong_rand_bytes(100),
                                        UserConfig)),
    ok.

-define(KEY, "cs512-key").

verify_cs512(UserConfig, BucketName) ->
    ?assertEqual(ok, erlcloud_s3:create_bucket(BucketName, UserConfig)),
    put_and_get(UserConfig, BucketName, <<"OLD">>),
    put_and_get(UserConfig, BucketName, <<"NEW">>),
    erlcloud_s3:delete_object(BucketName, ?KEY, UserConfig),
    assert_notfound(UserConfig, BucketName),
    ok.

put_and_get(UserConfig, BucketName, Data) ->
    erlcloud_s3:put_object(BucketName, ?KEY, Data, UserConfig),
    Props = erlcloud_s3:get_object(BucketName, ?KEY, UserConfig),
    ?assertEqual(proplists:get_value(content, Props), Data).

verify_cs770({{UserConfig, _}, {RiakNodes, _}}, BucketName) ->
    %% put object and cancel it;
    ?assertEqual(ok, erlcloud_s3:create_bucket(BucketName, UserConfig)),
    Key = "foobar",
    logger:debug("starting cs770 verification: ~s ~s", [BucketName, Key]),

    {ok, Socket} = rtcs_object:upload(UserConfig,
                                      {normal_partial, 3*1024*1024, 1024*1024},
                                      BucketName, Key),

    [[{UUID, M}]] = get_manifests(RiakNodes, BucketName, Key),

    %% Even if CS is smart enough to remove canceled upload, at this
    %% time the socket will be still alive, so no cancellation logic
    %% shouldn't be triggerred.
    ?assertEqual(writing, M?MANIFEST.state),
    logger:debug("UUID of ~s ~s: ~p", [BucketName, Key, UUID]),

    %% Emulate socket error with {error, closed} at server
    ok = gen_tcp:close(Socket),
    %% This wait is just for convenience
    timer:sleep(1000),
    rt:wait_until(fun() ->
                          [[{UUID, Mx}]] = get_manifests(RiakNodes, BucketName, Key),
                          scheduled_delete =:= Mx?MANIFEST.state
                  end, 8, 4096),

    Pbc = rtcs:pbc(RiakNodes, objects, BucketName),

    %% verify that object is also stored in latest GC bucket
    Ms = all_manifests_in_gc_bucket(Pbc),
    logger:info("Retrieved ~p manifets from GC bucket", [length(Ms)]),
    ?assertMatch(
       [{UUID, _}],
       lists:filter(fun({UUID0, M1}) when UUID0 =:= UUID ->
                            ?assertEqual(pending_delete, M1?MANIFEST.state),
                            true;
                       ({UUID0, _}) ->
                            logger:debug("UUID=~p / ~p", [mochihex:to_hex(UUID0), mochihex:to_hex(UUID)]),
                            false;
                       (_Other) ->
                            logger:error("Unexpected: ~p", [_Other]),
                            false
                    end, Ms)),

    logger:info("cs770 verification ok", []),
    ?assertEqual(ok, erlcloud_s3:delete_bucket(BucketName, UserConfig)),
    ok.

all_manifests_in_gc_bucket(Pbc) ->
    {ok, Keys} = riakc_pb_socket:list_keys(Pbc, ?GC_BUCKET),
    Ms = rt:pmap(fun(K) ->
                         {ok, O} = riakc_pb_socket:get(Pbc, <<"riak-cs-gc">>, K),
                         Some = [binary_to_term(V) || {_, V} <- riakc_obj:get_contents(O),
                                                      V =/= <<>>],
                         twop_set:to_list(twop_set:resolve(Some))
                 end, Keys),
    %% logger:debug("All manifests in GC buckets: ~p", [Ms]),
    lists:flatten(Ms).

get_manifests(RiakNodes, BucketName, Key) ->
    rt:wait_until(fun() ->
                          case rc_helper:get_riakc_obj(RiakNodes, objects, BucketName, Key) of
                              {ok, _} -> true;
                              Error -> Error
                          end
                  end, 8, 500),
    {ok, Obj} = rc_helper:get_riakc_obj(RiakNodes, objects, BucketName, Key),
    %% Assuming no tombstone;
    [binary_to_term(V) || {_, V} <- riakc_obj:get_contents(Obj),
                          V =/= <<>>].

verify_cs756({{UserConfig, _}, {RiakNodes, _}}, BucketName) ->
    %% Making sure API call to CS failed Riak KV underneath, all fails in 500
    %% This could be done with eqc
    logger:info("CS756 regression"),
    [rt:stop(RiakNode) || RiakNode <- RiakNodes],
    [rt:wait_until_unpingable(RiakNode) || RiakNode <- RiakNodes],

    %% test Object APIs before bucket creation
    ?assert500(erlcloud_s3:put_object(BucketName, "mine", <<"deadbeef">>, UserConfig)),
    ?assert500(erlcloud_s3:get_object(BucketName, "mine", UserConfig)),

    %% test bucket creation fails
    ?assert500(erlcloud_s3:create_bucket(BucketName, UserConfig)),
    ?assert500(erlcloud_s3:delete_bucket("dummybucket", UserConfig)),

    ?assert500(erlcloud_s3:put_object(BucketName, "mine", <<"deadbeef">>, UserConfig)),
    ?assert500(erlcloud_s3:get_object(BucketName, "mine", UserConfig)),
    ?assert500(erlcloud_s3:delete_object(BucketName, "mine", UserConfig)),

    %% try copy
    ?assert500(erlcloud_s3:copy_object(BucketName, "destination",
                                       BucketName, "mine", UserConfig)),

    ?assert500(erlcloud_s3:delete_bucket("dummybucket", UserConfig)),
    ?assert500(erlcloud_s3:delete_bucket(BucketName, UserConfig)),

    ok.

assert_notfound(UserConfig, BucketName) ->
    ?assertException(_,
                     {aws_error, {http_error, 404, _, _}},
                     erlcloud_s3:get_object(BucketName, ?KEY, UserConfig)).
