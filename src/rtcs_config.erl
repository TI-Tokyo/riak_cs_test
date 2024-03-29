%% ---------------------------------------------------------------------
%%
%% Copyright (c) 2007-2013 Basho Technologies, Inc.  All Rights Reserved.
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
-module(rtcs_config).
-compile(export_all).
-compile(nowarn_export_all).

-define(RIAK_CURRENT, <<"build_paths.riak_current">>).
-define(RIAK_PREVIOUS, <<"build_paths.riak_previous">>).
-define(CS_CURRENT, <<"build_paths.cs_current">>).
-define(CS_PREVIOUS, <<"build_paths.cs_previous">>).

-define(REQUEST_POOL_SIZE, 8).
-define(BUCKET_LIST_POOL_SIZE, 2).

request_pool_size() ->
    ?REQUEST_POOL_SIZE.

bucket_list_pool_size() ->
    ?BUCKET_LIST_POOL_SIZE.

configs(CustomConfigs) ->
    configs(CustomConfigs, current).

configs(CustomConfigs, current) ->
    merge(default_configs(), CustomConfigs);
configs(CustomConfigs, previous) ->
    merge(previous_default_configs(), CustomConfigs).

previous_configs() ->
    previous_configs([]).

previous_configs(CustomConfigs) ->
    merge(previous_default_configs(), CustomConfigs).

default_configs() ->
    [{riak, riak_config()},
     {cs, cs_config()}].

previous_default_configs() ->
    [{riak, previous_riak_config()},
     {cs, previous_cs_config()}].

pb_port(N) when is_integer(N) ->
    10000 + (N * 10) + 7;
pb_port(Node) ->
    pb_port(rtcs_dev:node_id(Node)).

cs_port(N) when is_integer(N) ->
    15008 + 10 * N;
cs_port(Node) ->
    cs_port(rtcs_dev:node_id(Node)).

stanchion_port() -> 8085.

riak_conf() ->
    [{"ring_size", "8"},
     {"buckets.default.merge_strategy", "2"}].

riak_config(CustomConfig) ->
    orddict:merge(fun(_, LHS, RHS) -> LHS ++ RHS end,
                  orddict:from_list(lists:sort(CustomConfig)),
                  orddict:from_list(lists:sort(riak_config()))).

riak_config() ->
    riak_config(
      current,
      ?CS_CURRENT,
      rt_config:get(backend, {multi_backend, bitcask, eleveldb})).

riak_config(Vsn, CsVsn, Backend) ->
    CSPath = rt_config:get(CsVsn),
    AddPaths = filelib:wildcard(CSPath ++ "/dev/dev1/riak-cs/lib/riak_cs*/ebin"),
    [
     riak_core_config(Vsn),
     repl_config(),
     {riak_api,
      [{pb_backlog, 256}]},
     {riak_kv,
      [{add_paths, AddPaths}] ++
          backend_config(CsVsn, Backend)
      }
    ].

riak_core_config(current) ->
    {riak_core,
     [{schema_dirs, ["./share/schema"]},
      {default_bucket_props, [{allow_mult, true}]},
      {ring_creation_size, 8}]
    };
riak_core_config(previous) ->
    {riak_core,
     [{schema_dirs, ["./share/schema"]},
      {default_bucket_props, [{allow_mult, true}]},
      {ring_creation_size, 8}]
    }.

backend_config(_CsVsn, memory) ->
    [{storage_backend, riak_kv_memory_backend}];
backend_config(_CsVsn, eleveldb) ->
    [{storage_backend, riak_kv_eleveldb_backend}];
backend_config(_CsVsn, leveled) ->
    [{storage_backend, riak_kv_leveled_backend}];
backend_config(_CSVsn, {multi_backend, BlocksBackend, DefaultBackend}) ->
    [
     {storage_backend, riak_cs_kv_multi_backend},
     {multi_backend_prefix_list, [{<<"0b:">>, be_blocks}]},
     {multi_backend_default, be_default},
     {multi_backend,
      [default_backend_config(DefaultBackend),
       blocks_backend_config(BlocksBackend)
      ]}
    ];
backend_config(?CS_CURRENT, prefix_multi) ->
    [
     {storage_backend, riak_kv_multi_prefix_backend}
    ];
backend_config(_OlderCsVsn, prefix_multi) ->
    [
     {storage_backend, riak_kv_multi_prefix_backend}
    ].

default_backend_config(eleveldb) ->
    {be_default, riak_kv_eleveldb_backend,
     [
      {max_open_files, 20},
      {data_root, "./data/leveldb"}
     ]};
default_backend_config(leveled) ->  %% doesn't work
    {be_default, riak_kv_leveled_backend,
     [
      {data_root, "./data/leveled"}
     ]}.

blocks_backend_config(fs) ->
    {be_blocks, riak_kv_fs2_backend, [{data_root, "./data/fs2"},
                                      {block_size, 1050000}]};
blocks_backend_config(_) ->
    {be_blocks, riak_kv_bitcask_backend, [{data_root, "./data/bitcask"}]}.


repl_config() ->
    {riak_repl,
     [
      {fullsync_on_connect, false},
      {fullsync_interval, disabled},
      {proxy_get, enabled}
     ]}.

previous_riak_config() ->
    riak_config(
      previous,
      ?CS_PREVIOUS,
      rt_config:get(backend, {multi_backend, bitcask, eleveldb})).

previous_riak_config(CustomConfig) ->
    orddict:merge(fun(_, LHS, RHS) -> LHS ++ RHS end,
                  orddict:from_list(lists:sort(CustomConfig)),
                  orddict:from_list(lists:sort(previous_riak_config()))).

previous_cs_config() ->
    previous_cs_config([], []).

previous_cs_config(UserExtra) ->
    previous_cs_config(UserExtra, []).

previous_cs_config(UserExtra, OtherApps) ->
    [
     {riak_cs,
      UserExtra ++
          [
           {connection_pools,
            [
             {request_pool, {request_pool_size(), 0} },
             {bucket_list_pool, {bucket_list_pool_size(), 0} }
            ]},
           {block_get_max_retries, 1},
           {proxy_get, disabled},  %% to prevent clustering and running foul of RpbGetClusterId issues
           {admin_key, "admin-key"},
           {anonymous_user_creation, true},
           {riak_pb_port, 10017},
           {cs_version, 030100}
          ]
     }] ++ OtherApps.

cs_config() ->
    cs_config([], []).

cs_config(UserExtra) ->
    cs_config(UserExtra, []).

cs_config(UserExtra, OtherApps) ->
    [
     {riak_cs,
      UserExtra ++
          [
           {connection_pools,
            [
             {request_pool, {request_pool_size(), 0} },
             {bucket_list_pool, {bucket_list_pool_size(), 0} }
            ]},
           {anonymous_user_creation, true},
           {admin_key, "admin-key"},
           {riak_host, {"127.0.0.1", 10017}},
           {proxy_get, enabled},
           {cs_version, 030203}
          ]
     }] ++ OtherApps.

replace(Key, Value, Config0) ->
    Config1 = proplists:delete(Key, Config0),
    [proplists:property(Key, Value)|Config1].


cs_current() ->
    ?CS_CURRENT.

devpath(riak, current) -> rt_config:get(?RIAK_CURRENT);
devpath(riak, previous) -> rt_config:get(?RIAK_PREVIOUS);
devpath(cs, current) -> rt_config:get(?CS_CURRENT);
devpath(cs, previous) -> rt_config:get(?CS_PREVIOUS).

set_configs(NumNodes, Config, Vsn) ->
    rtcs_dev:set_conf({riak, Vsn}, riak_conf()),
    rt:pmap(fun(N) ->
                    rtcs_dev:update_app_config(
                      rtcs_dev:riak_node(N), Vsn,
                      proplists:get_value(riak, Config)),
                    update_cs_config(devpath(cs, Vsn), N,
                                     proplists:get_value(cs, Config))
            end,
            lists:seq(1, NumNodes)),
    enable_zdbbl(Vsn).

read_config(Vsn, N) ->
    Prefix = devpath(cs, Vsn),
    EtcPath = rtcs_exec:riakcs_etcpath(Prefix, N),
    case file:consult(EtcPath ++ "/advanced.config") of
         {ok, [Config]} ->
             Config;
         {error, enoent}->
             {ok, [Config]} = file:consult(EtcPath ++ "/app.config"),
             Config
     end.

update_cs_config(Prefix, N, Config, {AdminKey, _AdminSecret}) ->
    CSSection = proplists:get_value(riak_cs, Config),
    UpdConfig = [{riak_cs, update_admin_creds(CSSection, AdminKey)} |
                 proplists:delete(riak_cs, Config)],
    update_cs_config(Prefix, N, UpdConfig).

update_cs_config(Prefix, N, Config) ->
    CSSection = proplists:get_value(riak_cs, Config),
    UpdConfig = [{riak_cs, update_cs_port(CSSection, N)} |
                 proplists:delete(riak_cs, Config)],
    update_app_config(rtcs_exec:riakcs_etcpath(Prefix, N), UpdConfig).

update_admin_creds(Config, AdminKey) ->
    [{admin_key, AdminKey}|
     proplists:delete(admin_key, Config)].

update_cs_port(Config, N) ->
    lists:foldl(
      fun({K, V}, Acc) -> lists:keystore(K, 1, Acc, {K, V}) end,
      Config,
      [{riak_host, {"127.0.0.1", pb_port(N)}},
       {listener, {"0.0.0.0", cs_port(N)}}
      ]).

update_app_config(Path, Config) ->
    logger:debug("update_app_config(~s,~p)", [Path, Config]),
    FileFormatString = "~s/~s.config",
    AdvConfigFile = io_lib:format(FileFormatString, [Path, "advanced"]),
    rtcs_dev:update_app_config_file(AdvConfigFile, Config).

enable_zdbbl(Vsn) ->
    Fs = filelib:wildcard(filename:join([devpath(riak, Vsn),
                                         "dev", "dev*", "etc", "vm.args"])),
    logger:debug("enable_zdbbl for vm.args : ~p", [Fs]),
    [os:cmd("sed -i -e 's/##+zdbbl /+zdbbl /g' " ++ F) || F <- Fs],
    ok.

merge(BaseConfig, undefined) ->
    BaseConfig;
merge(BaseConfig, Config) ->
    logger:debug("Merging Config: BaseConfig=~p", [BaseConfig]),
    logger:debug("Merging Config: Config=~p", [Config]),
    MergeA = orddict:from_list(Config),
    MergeB = orddict:from_list(BaseConfig),
    MergedConfig = orddict:merge(fun internal_merge/3, MergeA, MergeB),
    logger:debug("Merged config: ~p", [MergedConfig]),
    MergedConfig.

internal_merge(_Key, [{_, _}|_] = VarsA, [{_, _}|_] = VarsB) ->
    MergeC = orddict:from_list(VarsA),
    MergeD = orddict:from_list(VarsB),
    orddict:merge(fun internal_merge/3, MergeC, MergeD);
internal_merge(_Key, VarsA, _VarsB) ->
    VarsA.

%% @doc update current app.config, assuming CS is already stopped
upgrade_cs(N, AdminCreds) ->
    migrate_cs(previous, current, N, AdminCreds).

%% @doc update config file from `From' to `To' version.
migrate_cs(From, To, N, AdminCreds) ->
    migrate(From, To, N, AdminCreds).

migrate(From, To, N, AdminCreds) when
      (From =:= current andalso To =:= previous)
      orelse ( From =:= previous andalso To =:= current) ->
    Config0 = read_config(From, N),
    Config1 = migrate_config(From, To, Config0, cs),
    Prefix = devpath(cs, To),
    update_cs_config(Prefix, N, Config1, AdminCreds).

migrate_config(previous, current, Conf, cs) ->
    {AddList, RemoveList} = diff_config(cs_config([{anonymous_user_creation, false}]),
                                        previous_cs_config()),
    migrate_config(Conf, AddList, RemoveList);
migrate_config(current, previous, Conf, cs) ->
    {AddList, RemoveList} = diff_config(previous_cs_config(), cs_config()),
    migrate_config(Conf, AddList, RemoveList).

migrate_config(Conf0, AddList, RemoveList) ->
    RemoveFun = fun(Key, Config) ->
                  InnerConf0 = proplists:get_value(Key, Config),
                  InnerRemoveList = proplists:get_value(Key, RemoveList),
                  InnerConf1 = lists:foldl(fun proplists:delete/2,
                                           InnerConf0,
                                           proplists:get_keys(InnerRemoveList)),
                  replace(Key, InnerConf1, Config)
          end,
    Conf1 = lists:foldl(RemoveFun, Conf0, proplists:get_keys(RemoveList)),

    AddFun = fun(Key, Config) ->
                  InnerConf = proplists:get_value(Key, Config)
                              ++ proplists:get_value(Key, AddList),
                  replace(Key, InnerConf, Config)
             end,
    lists:foldl(AddFun, Conf1, proplists:get_keys(AddList)).

diff_config(Conf, BaseConf)->
    Keys = lists:umerge(proplists:get_keys(Conf),
                        proplists:get_keys(BaseConf)),

    Fun = fun(Key, {AddList, RemoveList}) ->
                  {Add, Remove} = diff_props(proplists:get_value(Key,Conf),
                                             proplists:get_value(Key, BaseConf)),
                  case {Add, Remove} of
                      {[], []} ->
                          {AddList, RemoveList};
                      {{}, Remove} ->
                          {AddList, RemoveList++[{Key, Remove}]};
                      {Add, []} ->
                          {AddList++[{Key, Add}], RemoveList};
                      {Add, Remove} ->
                          {AddList++[{Key, Add}], RemoveList++[{Key, Remove}]}
                  end
          end,
    lists:foldl(Fun, {[], []}, Keys).

diff_props(undefined, BaseProps) ->
    {[], BaseProps};
diff_props(Props, undefined) ->
    {Props, []};
diff_props(Props, BaseProps) ->
    Keys = lists:umerge(proplists:get_keys(Props),
                        proplists:get_keys(BaseProps)),
    Fun = fun(Key, {Add, Remove}) ->
                  Values = {proplists:get_value(Key, Props),
                            proplists:get_value(Key, BaseProps)},
                  case Values of
                      {undefined, V2} ->
                          {Add, Remove++[{Key, V2}]};
                      {V1, undefined} ->
                          {Add++[{Key, V1}], Remove};
                      {V, V} ->
                          {Add, Remove};
                      {V1, V2} ->
                          {Add++[{Key, V1}], Remove++[{Key, V2}]}
                  end
          end,
    lists:foldl(Fun, {[], []}, Keys).

