%% -------------------------------------------------------------------
%%
%% Copyright (c) 2013-2016 Basho Technologies, Inc.
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

-module(rtcs_dev).

-export([assert_error_log_empty/1, assert_error_log_empty/2,
         cmd/1, cmd/2,
         cs_node/1,
         datetime/0, datetime/1,
         get_deps/0,
         get_node_logs/0,
         get_version/0,
         json_get/2,
         load_cs_modules_for_riak_pipe_fittings/3,
         node_id/1,
         node_version/1,
         pbc/3, pbc/4,
         relpath/1,
         restore_configs/2,
         riak_id_per_cluster/1,
         riak_node/1,
         riak_root_and_vsn/1,
         set_advanced_conf/2,
         set_conf/2,
         setup/1, setup/2, setup/3,
         setup2x2/1,
         setupNxMsingles/2, setupNxMsingles/4,
         setup_admin_user/2,
         setup_clusters/1,
         setup_harness/2,
         spawn_cmd/1, spawn_cmd/2,
         start/1, start/2,
         stop/1, stop/2,
         teardown/0,
         truncate_error_log/1,
         update_app_config/2,
         update_app_config_file/2,
         upgrade/3,
         versions/0,
         whats_up/0
        ]).

-include_lib("eunit/include/eunit.hrl").
-include_lib("erlcloud/include/erlcloud_aws.hrl").

-define(BUILD_PATHS, (rt_config:get(build_paths))).

-define(RIAK_ROOT, <<"build_paths.root">>).

-define(DEVS(N), lists:concat(["dev", N, "@127.0.0.1"])).
-define(DEV(N), list_to_atom(?DEVS(N))).
-define(CSDEVS(N), lists:concat(["rcs-dev", N, "@127.0.0.1"])).
-define(CSDEV(N), list_to_atom(?CSDEVS(N))).

get_deps() ->
    lists:flatten(io_lib:format("~s/dev/dev1/riak-cs/lib", [relpath(cs_current)])).

relpath(Vsn) ->
    Path = ?BUILD_PATHS,
    path(Vsn, Path).

path(Key, [{Key, Path} | _]) ->
    Path;
path(Key, [{_, _} | Paths]) ->
    path(Key, Paths);
path(current, Path) ->
    Path;
path(root, Path) ->
    Path;
path(Key, _) ->
    Err = io_lib:format("Path '~p' requested but no value provided", [Key]),
    throw(lists:flatten(Err)).

setup_harness(_Test, _Args) ->
    logger:debug("Cleaning up lingering pipe directories"),
    rt:pmap(fun(Dir) ->
                    %% when joining two absolute paths, filename:join intentionally
                    %% throws away the first one. ++ gets us around that, while
                    %% keeping some of the security of filename:join.
                    %% the extra slashes will be pruned by filename:join, but this
                    %% ensures that there will be at least one between "/tmp" and Dir
                    PipeDir = filename:join(["/tmp//" ++ Dir, "dev"]),
                    %% when using filelib:wildcard/2, there must be a wildchar char
                    %% before the first '/'.
                    Files = filelib:wildcard("dev?/*.{r,w}", PipeDir),
                    [ file:delete(filename:join(PipeDir, File)) || File <- Files],
                    file:del_dir(PipeDir)
            end, devpaths()),
    ok.

devpaths() ->
    lists:usort([ DevPath || {Name, DevPath} <- rt_config:get(build_paths),
                             not lists:member(Name, [root, ee_root, cs_root])
                ]).

teardown() ->
    ok.



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

    create_snmp_dirs(RiakNodes),
    clean_data_dir(RiakNodes, "*"),

    rt:pmap(fun(N) -> start(N, Vsn) end, RiakNodes),
    rt:wait_for_service(RiakNodes, riak_kv),

    logger:info("Preparing a tussle of ~b riak and ~b cs nodes", [length(RiakNodes), length(CSNodes)]),
    JoinFun(RiakNodes),
    ok = rt:wait_until_nodes_ready(RiakNodes),
    ok = rt:wait_until_no_pending_changes(RiakNodes),
    ok = rt:wait_until_ring_converged(RiakNodes),

    rt:pmap(fun(N) ->
                    start(N, Vsn),
                    rt:wait_until_pingable(N)
            end, CSNodes),
    logger:info("Tussle ready", []),

    Nodes.

create_snmp_dirs(Nodes) ->
    Snmp = [node_path(Node) ++ "/data/snmp/agent/db" || Node <- Nodes],
    [?assertCmd("mkdir -p " ++ Dir) || Dir <- Snmp].

clean_data_dir(Nodes, SubDir) when is_list(Nodes) ->
    DataDirs = [node_path(Node) ++ "/data/" ++ SubDir || Node <- Nodes],
    lists:foreach(fun rm_rf/1, DataDirs).

rm_rf(Dir) ->
    logger:debug("Removing directory ~s", [Dir]),
    ?assertCmd("rm -rf " ++ Dir),
    ?assertEqual(false, filelib:is_dir(Dir)).


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

    {_RiakRoot, RiakVsn} = riak_root_and_vsn(Vsn),

    VersionMap = lists:zip(lists:seq(1, NumNodes), lists:duplicate(NumNodes, RiakVsn)),
    logger:debug("VersionMap: ~p", [VersionMap]),
    rt_config:set(rt_versions, VersionMap),

    create_or_restore_config_backups(RiakNodes ++ CSNodes, Vsn),

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

create_or_restore_config_backups(Nodes, Vsn) ->
    lists:foreach(
      fun(Node) ->
              ClusterPath = cluster_devpath(Node, Vsn),
              NodePath = node_path(Node, Vsn),
              ConfFile = io_lib:format("~s/etc/~s.conf", [NodePath, rtdev:which_riak(ClusterPath)]),
              AdvCfgFile = io_lib:format("~s/etc/advanced.config", [NodePath]),
              [begin
                   case filelib:is_regular(F ++ ".backup") of
                       true ->
                           logger:debug("found existing backup of ~s; restoring it", [F]),
                           [] = os:cmd(io_lib:format("cp -a \"~s.backup\" \"~s\"", [F, F]));
                       false ->
                           logger:debug("backing up ~s", [F]),
                           [] = os:cmd(io_lib:format("cp -a \"~s\" \"~s.backup\"", [F, F]))
                   end
               end || F <- [ConfFile, AdvCfgFile]]
      end,
      Nodes).

cluster_devpath(Node, Vsn) ->
    case atom_to_binary(Node, latin1) of
        <<"dev", _/binary>> ->
            devpath(riak, Vsn);
        <<"rcs-dev", _/binary>> ->
            devpath(cs, Vsn)
    end.



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
    logger:info("set_conf(all, ~p)", [NameValuePairs]),
    [ set_conf(DevPath, NameValuePairs) || DevPath <- devpaths()],
    ok;
set_conf(Name, NameValuePairs) when Name =:= riak;
                                    Name =:= cs ->
    set_conf({Name, current}, NameValuePairs),
    ok;
set_conf({Name, Vsn}, NameValuePairs) ->
    logger:debug("set_conf({~p, ~p}, ~p)", [Name, Vsn, NameValuePairs]),
    set_conf(devpath(Name, Vsn), NameValuePairs),
    ok;
set_conf({Name, Vsn, N}, NameValuePairs) ->
    logger:debug("set_conf({~p, ~p, ~p}, ~p)", [Name, Vsn, N, NameValuePairs]),
    rtdev:append_to_conf_file(get_conf(devpath(Name, Vsn), N), NameValuePairs),
    ok;
set_conf(Node, NameValuePairs) when is_atom(Node) ->
    rtdev:append_to_conf_file(get_conf(Node), NameValuePairs),
    ok;
set_conf(DevPath, NameValuePairs) ->
    logger:debug("set_conf(~p, ~p)", [DevPath, NameValuePairs]),
    [rtdev:append_to_conf_file(RiakConf, NameValuePairs) || RiakConf <- all_the_files(DevPath, "etc/*.conf")],
    ok.

all_the_files(DevPath, File) ->
    filelib:wildcard(io_lib:format("~s/dev/dev?/~s/~s", [DevPath, rtdev:which_riak(DevPath), File])).

set_advanced_conf(all, NameValuePairs) ->
    logger:debug("set_advanced_conf(all, ~p)", [NameValuePairs]),
    [ set_advanced_conf(DevPath, NameValuePairs) || DevPath <- devpaths()],
    ok;
set_advanced_conf(Name, NameValuePairs) when Name =:= riak orelse
                                             Name =:= cs ->
    set_advanced_conf({Name, current}, NameValuePairs),
    ok;
set_advanced_conf({Name, Vsn}, NameValuePairs) ->
    logger:debug("set_advanced_conf({~p, ~p}, ~p)", [Name, Vsn, NameValuePairs]),
    set_advanced_conf(devpath(Name, Vsn), NameValuePairs),
    ok;
set_advanced_conf({Name, Vsn, N}, NameValuePairs) ->
    logger:debug("set_advanced_conf({~p, ~p, ~p}, ~p)", [Name, Vsn, N, NameValuePairs]),
    update_app_config_file(
      get_app_config(
        devpath(Name, Vsn), N), NameValuePairs),
    ok;
set_advanced_conf(Node, NameValuePairs) when is_atom(Node) ->
    update_app_config_file(get_app_config(Node), NameValuePairs),
    ok;
set_advanced_conf(DevPath, NameValuePairs) ->
    Confs = all_the_files(DevPath, "etc/advanced.config"),
    ?assertNotEqual(Confs, []),
    [update_app_config_file(RiakConf, NameValuePairs) || RiakConf <- Confs],
    ok.

devpath(Name, Vsn) ->
    rtcs_config:devpath(Name, Vsn).

get_conf(Node) ->
    N = node_id(Node),
    Path = relpath(node_version(N)),
    get_conf(Path, N).

get_conf(DevPath, N) ->
    WildCard = io_lib:format("~s/dev/dev~b/~s/etc/*.conf", [DevPath, N, rtdev:which_riak(DevPath)]),
    [Conf] = filelib:wildcard(WildCard),
    Conf.

get_app_config(Node) ->
    get_app_config(Node, current).
get_app_config(Node, Vsn) when is_atom(Node) ->
    Path = node_path(Node, Vsn),
    io_lib:format("~s/etc/advanced.config", [Path]);
get_app_config(DevPath, N) ->
    io_lib:format("~s/dev/dev~b/~s/etc/advanced.config", [DevPath, N, rtdev:which_riak(DevPath)]).

update_app_config(all, Config) ->
    [ update_app_config(DevPath, Config) || DevPath <- devpaths()];
update_app_config(Node, Config) when is_atom(Node) ->
    Path = node_path(Node, current),
    FileFormatString = "~s/etc/~s.config",

    AppConfigFile = io_lib:format(FileFormatString, [Path, "app"]),
    AdvConfigFile = io_lib:format(FileFormatString, [Path, "advanced"]),
    %% If there's an app.config, do it old style
    %% if not, use cuttlefish's adavnced.config
    case filelib:is_file(AppConfigFile) of
        true ->
            update_app_config_file(AppConfigFile, Config);
        _ ->
            update_app_config_file(AdvConfigFile, Config)
    end.

update_app_config_file(ConfigFile, Config) ->
    logger:debug("update_app_config_file(~s, ~s)", [ConfigFile, io_lib:format("\n~p\n", [Config])]),

    BaseConfig =
        case file:consult(ConfigFile) of
            {ok, [ValidConfig]} ->
                ValidConfig;
            {error, enoent} ->
                logger:warning("~s not found", [ConfigFile]),
                []
        end,
    MergeA = orddict:from_list(Config),
    MergeB = orddict:from_list(BaseConfig),
    NewConfig =
        orddict:merge(fun(_, VarsA, VarsB) ->
                              MergeC = orddict:from_list(VarsA),
                              MergeD = orddict:from_list(VarsB),
                              orddict:merge(fun(_, ValA, _ValB) ->
                                                    ValA
                                            end, MergeC, MergeD)
                      end, MergeA, MergeB),
    NewConfigOut = io_lib:format("~p.", [NewConfig]),
    ?assertEqual(ok, file:write_file(ConfigFile, NewConfigOut)),
    ok.


node_path(Node) ->
    node_path(Node, current).
node_path(Node, Vsn)
  when is_atom(Node) andalso (Vsn == current orelse Vsn == previous) ->
    ClusterDevpath = cluster_devpath(Node, Vsn),
    io_lib:format("~s/dev/dev~b/~s", [ClusterDevpath, node_id(Node), rtdev:which_riak(ClusterDevpath)]).




assert_error_log_empty(N) ->
    assert_error_log_empty(current, N).

assert_error_log_empty(Vsn, N) ->
    ErrorLog = riakcs_logpath(rtcs_config:devpath(cs, Vsn), N, "error.log"),
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
    ErrorLog = riakcs_logpath(rt_config:get(rtcs_config:cs_current()), N, "error.log"),
    logger:info("truncating ~s", [ErrorLog]),
    "" = os:cmd("rm -f " ++  ErrorLog).

riakcs_logpath(Prefix, N, File) ->
    io_lib:format("~s/dev/dev~b/riak-cs/log/~s", [Prefix, N, File]).

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



upgrade(Node, NewVersion, _CB) ->
    N = node_id(Node),
    Version = node_version(N),
    logger:info("Upgrading ~p : ~p -> ~p", [Node, Version, NewVersion]),
    OldPath = relpath(Version),
    NewPath = relpath(NewVersion),
    WhichRiak = rtdev:which_riak(OldPath),

    Commands = [
        io_lib:format("rm -rf \"~s/dev/dev~b/~s/data/leveldb\"", [NewPath, N, WhichRiak]),
        io_lib:format("rm -rf \"~s/dev/dev~b/~s/data/leveled\"", [NewPath, N, WhichRiak]),
        io_lib:format("rm -rf \"~s/dev/dev~b/~s/data/bitcask\"", [NewPath, N, WhichRiak]),
        io_lib:format("rm -rf \"~s/dev/dev~b/~s/data/ring\"", [NewPath, N, WhichRiak]),
        io_lib:format("cp -p -P -R \"~s/dev/dev~b/~s/data/leveldb\" \"~s/dev/dev~b/~s/data\"", [OldPath, N, WhichRiak, NewPath, N, WhichRiak]),
        io_lib:format("cp -p -P -R \"~s/dev/dev~b/~s/data/leveled\" \"~s/dev/dev~b/~s/data\"", [OldPath, N, WhichRiak, NewPath, N, WhichRiak]),
        io_lib:format("cp -p -P -R \"~s/dev/dev~b/~s/data/bitcask\" \"~s/dev/dev~b/~s/data\"", [OldPath, N, WhichRiak, NewPath, N, WhichRiak]),
        io_lib:format("cp -p -P -R \"~s/dev/dev~b/~s/data/ring\" \"~s/dev/dev~b/~s/data\"", [OldPath, N, WhichRiak, NewPath, N, WhichRiak])
    ],
    [ begin
        logger:info("Running: ~s", [Cmd]),
        os:cmd(Cmd)
    end || Cmd <- Commands],
    VersionMap = orddict:store(N, NewVersion, rt_config:get(rt_versions)),
    rt_config:set(rt_versions, VersionMap),
    ok.


-spec riak_root_and_vsn(atom()) -> {binary(), atom()}.
riak_root_and_vsn(current) -> {?RIAK_ROOT, current};
riak_root_and_vsn(previous) -> {?RIAK_ROOT, previous}.

-spec stop(node()) -> string().
stop(Node) ->
    stop(Node, current).
-spec stop(node(), current|previous) -> string().
stop(Node, Vsn) ->
    rtdev:run_riak(Node, cluster_devpath(Node, Vsn), "stop").

-spec start(node()) -> string().
start(Node) ->
    start(Node, current).
-spec start(node(), current|previous) -> string().
start(Node, Vsn) ->
    rtdev:run_riak(Node, cluster_devpath(Node, Vsn), "start").


-spec node_id(node()) -> non_neg_integer().
node_id(Node) ->
    NodeMap = rt_config:get(rt_nodes),
    orddict:fetch(Node, NodeMap).

node_version(N) ->
    VersionMap = rt_config:get(rt_versions),
    orddict:fetch(N, VersionMap).


spawn_cmd(Cmd) ->
    spawn_cmd(Cmd, []).
spawn_cmd(Cmd, Opts) when is_list(Cmd) ->
    spawn_cmd({spawn, Cmd}, Opts);
spawn_cmd({_, CmdName} = Cmd, Opts) ->
    logger:info("Executing \"~s\"", [CmdName]),
    open_port(Cmd, [stream, in, binary, exit_status, stderr_to_stdout] ++ Opts).

cmd(Cmd) ->
    cmd(Cmd, []).
cmd(Cmd, Opts) ->
    get_cmd_result(spawn_cmd(Cmd, Opts), <<>>, []).

get_cmd_result(Port, LineAcc, Acc) ->
    receive
        {Port, {exit_status, 0}} ->
            case LineAcc of
                <<>> ->
                    ok;
                _ ->
                    logger:info("[cmd] ~s (no eol)", [LineAcc])
            end,
            {ok, iolist_to_binary([Acc, LineAcc])};
        {Port, {exit_status, Status}} ->
            {error, {exit_status, Status}};
        {Port, {data, Line}} when size(Line) > 0 ->
            case lists:reverse(binary_to_list(Line)) of
                [$\n|_] ->
                    FullLine = <<LineAcc/binary, Line/binary>>,
                    logger:info("[cmd] ~s", [FullLine]),
                    get_cmd_result(Port, <<>>, Acc ++ binary_to_list(FullLine));
                _ ->
                    get_cmd_result(Port, <<LineAcc/binary, Line/binary>>, Acc)
            end
    end.



get_version() ->
    os:cmd("git describe --tags --exact-match HEAD 2>/dev/null").

whats_up() ->
    case [rpc:call(Node, os, cmd, ["pwd"]) || Node <- nodes()] of
        [] ->
            print_nothing;
        Up ->
            io:format("Here's what's running:\n"),
            [io:format("  ~s~n",[string:substr(Dir, 1, length(Dir)-1)]) || Dir <- Up, is_list(Dir)]
    end.


versions() ->
    proplists:get_keys(rt_config:get(build_paths)) -- [root].

get_node_logs() ->
    lists:flatmap(fun get_node_logs/1, [root, ee_root, cs_root]).

get_node_logs(Base) ->
    Root = filename:absname(proplists:get_value(Base, ?BUILD_PATHS)),
    %% Unlike Riak, Riak CS has multiple things in the root and so we need
    %% to distinguish between them.
    RootLen = length(filename:dirname(Root)) + 1, %% Remove the leading slash
    [ begin
          {ok, Port} = file:open(Filename, [read, binary]),
          {lists:nthtail(RootLen, Filename), Port}
      end || Filename <- filelib:wildcard(Root ++ "/*/dev/dev*/riak-cs/log/*") ].



restore_configs(Nodes, Vsn) ->
    lists:foreach(
      fun(Node) ->
              ClusterPath = cluster_devpath(Node, Vsn),
              NodePath = node_path(Node, Vsn),
              ConfFile = io_lib:format("~s/etc/~s.conf", [NodePath, rtdev:which_riak(ClusterPath)]),
              AdvCfgFile = io_lib:format("~s/etc/advanced.config", [NodePath]),
              [begin
                   case filelib:is_regular(F ++ ".backup") of
                       false ->
                           logger:debug("backup of ~s not found", [F]);
                       true ->
                           logger:debug("restoring ~s", [F]),
                           [] = os:cmd(io_lib:format("mv -f \"~s.backup\" \"~s\"", [F, F]))
                   end
               end || F <- [ConfFile, AdvCfgFile]]
      end,
      Nodes).


load_cs_modules_for_riak_pipe_fittings(CSNode, RiakNodes, Mods) ->
    lists:foreach(
      fun(N) ->
              lists:foreach(
                fun(M) ->
                        ExtPath = filename:dirname(rpc:call(CSNode, code, which, [M])),
                        rpc:call(N, code, add_pathz, [ExtPath]),
                        {module, _} = rpc:call(N, code, load_file, [M]) end,
                Mods)
      end, RiakNodes).

