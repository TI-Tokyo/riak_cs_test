%% ---------------------------------------------------------------------
%%
%% Copyright (c) 2007-2013 Basho Technologies, Inc.  All Rights Reserved.
%%               2022, 2023 TI Tokyo    All Rights Reserved.
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

-module(too_large_entity_test).

%% @doc `riak_test' module for testing the behavior in dealing with
%% entities that violate the specified object size restrictions

-export([confirm/0]).

-include("rtcs.hrl").
-include_lib("xmerl/include/xmerl.hrl").

-define(TEST_BUCKET, "riak-test-bucket").
-define(TEST_KEY1, "riak_test_key1").
-define(TEST_KEY2, "riak_test_key2").
-define(PART_COUNT, 5).
-define(GOOD_PART_SIZE, 5*1024*1024).
-define(BAD_PART_SIZE, 2*1024*1024).

confirm() ->
    {{UserConfig, _}, _} = rtcs_dev:setup(1, [{cs, cs_config()}]),

    ?assertNoBuckets(UserConfig),
    logger:info("User is valid on the cluster, and has no buckets"),

    ?assertHttpCode(404, erlcloud_s3:list_objects(?TEST_BUCKET, UserConfig)),

    logger:info("creating bucket ~p", [?TEST_BUCKET]),
    ?assertEqual(ok, erlcloud_s3:create_bucket(?TEST_BUCKET, UserConfig)),

    ?assertHasBucket(?TEST_BUCKET, UserConfig),

    %% Test cases
    too_large_upload_part_test_case(?TEST_BUCKET, ?TEST_KEY1, UserConfig),
    too_large_object_put_test_case(?TEST_BUCKET, ?TEST_KEY2, UserConfig),

    logger:info("deleting bucket ~p", [?TEST_BUCKET]),
    ?assertEqual(ok, erlcloud_s3:delete_bucket(?TEST_BUCKET, UserConfig)),

    ?assertHttpCode(404, erlcloud_s3:list_objects(?TEST_BUCKET, UserConfig)),

    pass.

generate_part_data(X, Size)
  when 0 =< X, X =< 255 ->
    list_to_binary(
      [X || _ <- lists:seq(1, Size)]).

too_large_upload_part_test_case(Bucket, Key, Config) ->
    %% Initiate a multipart upload
    logger:info("Initiating multipart upload"),
    {ok, InitUploadRes} = erlcloud_s3:start_multipart(Bucket, Key, [], [], Config),
    UploadId = proplists:get_value(uploadId, InitUploadRes),

    %% Verify the upload id is in list_uploads results and
    %% that the bucket information is correct
    {ok, MPU} = erlcloud_s3:list_multipart_uploads(Bucket, [], [], Config),
    Uploads = proplists:get_value(uploads, MPU),
    ?assert(lists:any(fun(P) -> proplists:get_value(uploadId, P) == UploadId end, Uploads)),

    {error, {http_error, 400, undefined, RespBody}} =
       erlcloud_s3:upload_part(Bucket, Key,
                               UploadId,
                               1, generate_part_data(61, 2000),
                               [], Config),
    {Xml, _} = xmerl_scan:string(binary_to_list(RespBody)),
    [#xmlElement{content = [#xmlText{value = "EntityTooLarge"}]}] =
        xmerl_xpath:string("/Error/Code", Xml, []),
    [#xmlElement{content = [#xmlText{value = Resource}]}] =
        xmerl_xpath:string("/Error/Resource", Xml, []),
    ?assert(0 < string:str(Resource, "/" ++ Bucket ++ "/objects/" ++ Key)),
    ok.

too_large_object_put_test_case(Bucket, Key, Config) ->
    Object1 = crypto:strong_rand_bytes(1001),
    Object2 = crypto:strong_rand_bytes(1000),

    ?assertHttpCode(400,
                    erlcloud_s3:put_object(Bucket, Key, Object1, Config)),

    erlcloud_s3:put_object(Bucket, Key, Object2, Config),

    ObjList1 = erlcloud_s3:list_objects(Bucket, Config),
    ?assertEqual([Key],
        [proplists:get_value(key, O) ||
            O <- proplists:get_value(contents, ObjList1)]),

    erlcloud_s3:delete_object(Bucket, Key, Config),

    ObjList2 = erlcloud_s3:list_objects(Bucket, Config),
    ?assertEqual([], proplists:get_value(contents, ObjList2)).


cs_config() ->
    [{riak_cs,
      [
       {max_content_length, 1000},
       {enforce_multipart_part_size, false}
      ]
     }].
