%% -------------------------------------------------------------------
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
%% -------------------------------------------------------------------

-module(rtcs).

-export([riak_node/1,
         cs_node/1,
         setup/1, setup/2, setup/3,
         setup2x2/1,
         setupNxMsingles/2, setupNxMsingles/4,
         riak_id_per_cluster/1,
         set_conf/2,
         set_advanced_conf/2,
         assert_error_log_empty/1, assert_error_log_empty/2,
         truncate_error_log/1,
         pbc/3, pbc/4,
         json_get/2,
         datetime/0, datetime/1
        ]).

-include_lib("eunit/include/eunit.hrl").
-include_lib("erlcloud/include/erlcloud_aws.hrl").

-define(DEVS(N), lists:concat(["dev", N, "@127.0.0.1"])).
-define(DEV(N), list_to_atom(?DEVS(N))).
-define(CSDEVS(N), lists:concat(["rcs-dev", N, "@127.0.0.1"])).
-define(CSDEV(N), list_to_atom(?CSDEVS(N))).


riak_node(N) ->
    ?DEV(N).

cs_node(N) ->
    ?CSDEV(N).


setup(NumNodes) ->
    setup(NumNodes, [], current).

setup(NumNodes, Configs) ->
    setup(NumNodes, Configs, current).

setup(NumNodes, Configs, Vsn) ->
    Flavor = rt_config:get(flavor, basic),
    logger:info("Flavor: ~p", [Flavor]),

    application:ensure_all_started(erlcloud),
    application:ensure_all_started(ibrowse),

    {_, [CSNode0|_]} = Nodes =
        flavored_setup(#{num_nodes => NumNodes,
                         flavor => Flavor,
                         config_spec => Configs,
                         vsn => Vsn}),

    AdminConfig = make_admin(Configs, NumNodes, Vsn, CSNode0),

    {AdminConfig, Nodes}.


setup2x2(Configs) ->
    {_, [CSNode0|_]} = Nodes = setup2x2_2(Configs),
    AdminConfig = make_admin(Configs, 4, current, CSNode0),
    {AdminConfig, Nodes}.

setup2x2_2(Configs) ->
    JoinFun = fun(Nodes) ->
                      [A,B,C,D] = Nodes,
                      rt:join(B,A),
                      rt:join(D,C)
              end,
    setup_clusters(#{config_spec => Configs,
                     join_fun => JoinFun,
                     num_nodes => 4,
                     vsn => current}).

%% 1 cluster with N nodes + M cluster with 1 node
setupNxMsingles(N, M) ->
    setupNxMsingles(N, M, [], current).

setupNxMsingles(N, M, Configs, Vsn)
  when Vsn =:= current orelse Vsn =:= previous ->
    JoinFun = fun(Nodes) ->
                      [Target | Joiners] = lists:sublist(Nodes, N),
                      [rt:join(J, Target) || J <- Joiners]
              end,
    setup_clusters(#{config_spec => Configs,
                     join_fun => JoinFun,
                     num_nodes => N + M,
                     vsn => Vsn}).

flavored_setup(#{num_nodes := NumNodes,
                 flavor := basic,
                 config_spec := Configs,
                 vsn := Vsn}) ->
    JoinFun = fun(Nodes) ->
                      [First|Rest] = Nodes,
                      [rt:join(Node, First) || Node <- Rest]
              end,
    setup_clusters(#{config_spec => Configs,
                     join_fun => JoinFun,
                     num_nodes => NumNodes,
                     vsn => Vsn});
flavored_setup(#{num_nodes := NumNodes,
                 flavor := {multibag, _} = Flavor,
                 config_spec := Configs,
                 vsn := Vsn})
  when Vsn =:= current orelse Vsn =:= previous ->
    rtcs_bag:flavored_setup(#{num_nodes => NumNodes,
                              flavor => Flavor,
                              config_spec => Configs,
                              vsn => Vsn}).

setup_clusters(#{config_spec := Configs,
                 join_fun := JoinFun,
                 num_nodes := NumNodes,
                 vsn := Vsn}) ->
    Nodes = {RiakNodes, CSNodes} =
        configure_clusters(#{num_nodes => NumNodes,
                             initial_config => Configs,
                             vsn => Vsn}),

    rtcs_dev:create_snmp_dirs(RiakNodes),
    rtcs_dev:clean_data_dir(RiakNodes, "*"),

    rt:pmap(fun(N) -> rtcs_dev:start(N, Vsn) end, RiakNodes),
    rt:wait_for_service(RiakNodes, riak_kv),

    logger:info("Preparing a tussle of ~b riak and ~b cs nodes", [length(RiakNodes), length(CSNodes)]),
    JoinFun(RiakNodes),
    ok = rt:wait_until_nodes_ready(RiakNodes),
    ok = rt:wait_until_no_pending_changes(RiakNodes),
    ok = rt:wait_until_ring_converged(RiakNodes),

    [N1|Nn] = CSNodes,
    %% let this node start stanchion
    rtcs_dev:start(N1, Vsn),
    rt:wait_until_pingable(N1),
    rt:pmap(fun(N) ->
                    rtcs_dev:start(N, Vsn),
                    rt:wait_until_pingable(N)
            end, Nn),
    logger:info("Tussle ready", []),

    Nodes.


%% Return Riak node IDs, one per cluster.
%% For example, in basic single cluster case, just return [1].
-spec riak_id_per_cluster(pos_integer()) -> [pos_integer()].
riak_id_per_cluster(NumNodes) ->
    case rt_config:get(flavor, basic) of
        basic -> [1];
        {multibag, _} = Flavor -> rtcs_bag:riak_id_per_cluster(NumNodes, Flavor)
    end.

configure_clusters(#{num_nodes := NumNodes,
                     initial_config := ConfigSpec,
                     vsn := Vsn}) ->
    {RiakNodes, CSNodes} = Nodes = {riak_nodes(NumNodes),
                                    cs_nodes(NumNodes)},

    NodeMap = orddict:from_list(
                lists:zip(RiakNodes, lists:seq(1, NumNodes))
                ++ lists:zip(CSNodes, lists:seq(1, NumNodes))),
    logger:debug("NodeMap: ~p", [NodeMap]),
    rt_config:set(rt_nodes, NodeMap),

    {_RiakRoot, RiakVsn} = rtcs_dev:riak_root_and_vsn(Vsn),

    VersionMap = lists:zip(lists:seq(1, NumNodes), lists:duplicate(NumNodes, RiakVsn)),
    logger:debug("VersionMap: ~p", [VersionMap]),
    rt_config:set(rt_versions, VersionMap),

    rtcs_dev:create_or_restore_config_backups(RiakNodes ++ CSNodes, Vsn),

    if is_function(ConfigSpec) ->
            rtcs_config:set_configs(NumNodes,
                                    rtcs_config:configs([], Vsn),
                                    Vsn),
            ConfigSpec(Nodes);
       el/=se ->
            rtcs_config:set_configs(NumNodes,
                                    rtcs_config:configs(ConfigSpec, Vsn),
                                    Vsn)
    end,
    Nodes.



make_admin(ConfigFun, NumNodes, Vsn, CSNode0) when is_function(ConfigFun) ->
    make_admin([], NumNodes, Vsn, CSNode0);
make_admin(Configs, NumNodes, Vsn, CSNode0) ->
    case ssl_options(Configs) of
        [] ->
            setup_admin_user(NumNodes, Vsn);
        _SSLOpts ->
            rtcs_admin:create_user_rpc(CSNode0, "admin-key", "admin-secret")
    end.

ssl_options(Config) ->
    case proplists:get_value(cs, Config) of
        undefined -> [];
        RiakCS ->
           case proplists:get_value(riak_cs, RiakCS) of
               undefined -> [];
               CSConfig ->
                   proplists:get_value(ssl, CSConfig, [])
           end
    end.

setup_admin_user(NumNodes, Vsn)
  when Vsn =:= current orelse Vsn =:= previous ->

    logger:info("Setting up admin user", []),
    %% Create admin user and set in cs and stanchion configs
    {AdminCreds, AdminUId} = rtcs_admin:create_admin_user(1),
    #aws_config{access_key_id=KeyID,
                secret_access_key=KeySecret} = AdminCreds,

    AdminConf = [{admin_key, KeyID}]
        ++ case Vsn of
               current -> [];
               previous -> [{admin_secret, KeySecret}]
           end,
    rt:pmap(fun(N) ->
                    set_advanced_conf({cs, Vsn, N}, [{riak_cs, AdminConf}])
            end, lists:seq(1, NumNodes)),

    UpdateFun = fun({Node, App}) ->
                        ok = rpc:call(Node, application, set_env,
                                      [App, admin_key, KeyID]),
                        ok = rpc:call(Node, application, set_env,
                                      [App, admin_secret, KeySecret])
                end,
    ZippedNodes = [{N, riak_cs} || N <- cs_nodes(NumNodes) ],
    lists:foreach(UpdateFun, ZippedNodes),

    {AdminCreds, AdminUId}.


-spec set_conf(atom() | {atom(), atom()} | string(), [{string(), string()}]) -> ok.
set_conf(all, NameValuePairs) ->
    logger:info("rtcs:set_conf(all, ~p)", [NameValuePairs]),
    [ set_conf(DevPath, NameValuePairs) || DevPath <- rtcs_dev:devpaths()],
    ok;
set_conf(Name, NameValuePairs) when Name =:= riak;
                                    Name =:= cs ->
    set_conf({Name, current}, NameValuePairs),
    ok;
set_conf({Name, Vsn}, NameValuePairs) ->
    logger:debug("rtcs:set_conf({~p, ~p}, ~p)", [Name, Vsn, NameValuePairs]),
    set_conf(rtcs_dev:devpath(Name, Vsn), NameValuePairs),
    ok;
set_conf({Name, Vsn, N}, NameValuePairs) ->
    logger:debug("rtcs:set_conf({~p, ~p, ~p}, ~p)", [Name, Vsn, N, NameValuePairs]),
    rtdev:append_to_conf_file(rtcs_dev:get_conf(rtcs_dev:devpath(Name, Vsn), N), NameValuePairs),
    ok;
set_conf(Node, NameValuePairs) when is_atom(Node) ->
    rtdev:append_to_conf_file(rtcs_dev:get_conf(Node), NameValuePairs),
    ok;
set_conf(DevPath, NameValuePairs) ->
    logger:debug("rtcs:set_conf(~p, ~p)", [DevPath, NameValuePairs]),
    [rtdev:append_to_conf_file(RiakConf, NameValuePairs) || RiakConf <- rtcs_dev:all_the_files(DevPath, "etc/*.conf")],
    ok.

set_advanced_conf(all, NameValuePairs) ->
    logger:debug("rtcs:set_advanced_conf(all, ~p)", [NameValuePairs]),
    [ set_advanced_conf(DevPath, NameValuePairs) || DevPath <- rtcs_dev:devpaths()],
    ok;
set_advanced_conf(Name, NameValuePairs) when Name =:= riak orelse
                                             Name =:= cs ->
    set_advanced_conf({Name, current}, NameValuePairs),
    ok;
set_advanced_conf({Name, Vsn}, NameValuePairs) ->
    logger:debug("rtcs:set_advanced_conf({~p, ~p}, ~p)", [Name, Vsn, NameValuePairs]),
    set_advanced_conf(rtcs_dev:devpath(Name, Vsn), NameValuePairs),
    ok;
set_advanced_conf({Name, Vsn, N}, NameValuePairs) ->
    logger:debug("rtcs:set_advanced_conf({~p, ~p, ~p}, ~p)", [Name, Vsn, N, NameValuePairs]),
    rtcs_dev:update_app_config_file(
      rtcs_dev:get_app_config(
        rtcs_dev:devpath(Name, Vsn), N), NameValuePairs),
    ok;
set_advanced_conf(Node, NameValuePairs) when is_atom(Node) ->
    rtcs_dev:update_app_config_file(rtcs_dev:get_app_config(Node), NameValuePairs),
    ok;
set_advanced_conf(DevPath, NameValuePairs) ->
    Confs = rtcs_dev:all_the_files(DevPath, "etc/advanced.config"),
    ?assertNotEqual(Confs, []),
    [rtcs_dev:update_app_config_file(RiakConf, NameValuePairs) || RiakConf <- Confs],
    ok.


assert_error_log_empty(N) ->
    assert_error_log_empty(current, N).

assert_error_log_empty(Vsn, N) ->
    ErrorLog = rtcs_config:riakcs_logpath(rtcs_config:devpath(cs, Vsn), N, "error.log"),
    case file:read_file(ErrorLog) of
        {error, enoent} -> ok;
        {ok, <<>>} -> ok;
        {ok, Errors} ->
            logger:warning("Not empty error.log (~s): the first few lines are...~n~s",
                           [ErrorLog,
                            lists:map(
                              fun(L) -> io_lib:format("cs dev~p error.log: ~s\n", [N, L]) end,
                              lists:sublist(binary:split(Errors, <<"\n">>, [global]), 3))]),
            error(not_empty_error_log)
    end.

truncate_error_log(N) ->
    Cmd = os:find_executable("rm"),
    ErrorLog = rtcs_config:riakcs_logpath(rt_config:get(rtcs_config:cs_current()), N, "error.log"),
    logger:info("truncating ~s", [ErrorLog]),
    ok = rtcs_exec:cmd(Cmd, [{args, ["-f", ErrorLog]}]).

%% Kind = objects | blocks | users | buckets ...
pbc(RiakNodes, ObjectKind, Opts) ->
    pbc(rt_config:get(flavor, basic), ObjectKind, RiakNodes, Opts).

pbc(basic, _ObjectKind, RiakNodes, _Opts) ->
    rt:pbc(hd(RiakNodes));
pbc({multibag, _} = Flavor, ObjectKind, RiakNodes, Opts) ->
    rtcs_bag:pbc(Flavor, ObjectKind, RiakNodes, Opts).

datetime() ->
    datetime(calendar:universal_time()).

datetime({{YYYY,MM,DD}, {H,M,S}}) ->
    lists:flatten(io_lib:format(
        "~4..0B~2..0B~2..0BT~2..0B~2..0B~2..0BZ", [YYYY, MM, DD, H, M, S])).

json_get(Key, Json) when is_binary(Key) ->
    json_get([Key], Json);
json_get([], Json) ->
    Json;
json_get([Key | Keys], {struct, JsonProps}) ->
    case lists:keyfind(Key, 1, JsonProps) of
        false ->
            notfound;
        {Key, Value} ->
            json_get(Keys, Value)
    end.

%% private

riak_nodes(NumNodes) ->
    [?DEV(N) || N <- lists:seq(1, NumNodes)].

cs_nodes(NumNodes) ->
    [?CSDEV(N) || N <- lists:seq(1, NumNodes)].

