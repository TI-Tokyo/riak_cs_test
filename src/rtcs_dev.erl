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

%% @private
-module(rtcs_dev).
-compile(export_all).
-compile(nowarn_export_all).
-include_lib("eunit/include/eunit.hrl").

-define(BUILD_PATHS, (rt_config:get(build_paths))).
-define(SRC_PATHS, (rt_config:get(src_paths))).

-define(RIAK_ROOT, <<"build_paths.root">>).

get_deps() ->
    lists:flatten(io_lib:format("~s/dev/dev1/riak-cs/lib", [relpath(cs_current)])).

setup_harness(_Test, _Args) ->

    lists:map(fun(X) -> clean_data_dir_all(X) end,
              devpaths()),

    lager:info("Cleaning up lingering pipe directories"),
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

pass() ->
    {Nodes, _} = lists:unzip(rt_config:get(rt_nodes)),
    restore_configs(Nodes, current),
    pass.


relpath(Vsn) ->
    Path = ?BUILD_PATHS,
    path(Vsn, Path).

srcpath(Vsn) ->
    Path = ?SRC_PATHS,
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

upgrade(Node, NewVersion, _CB) ->
    N = node_id(Node),
    Version = node_version(N),
    lager:info("Upgrading ~p : ~p -> ~p", [Node, Version, NewVersion]),
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
        lager:info("Running: ~s", [Cmd]),
        os:cmd(Cmd)
    end || Cmd <- Commands],
    VersionMap = orddict:store(N, NewVersion, rt_config:get(rt_versions)),
    rt_config:set(rt_versions, VersionMap),
    ok.

-spec riak_root_and_vsn(atom()) -> {binary(), atom()}.
riak_root_and_vsn(current) -> {?RIAK_ROOT, current};
riak_root_and_vsn(previous) -> {?RIAK_ROOT, previous}.

get_conf(Node) ->
    N = node_id(Node),
    Path = relpath(node_version(N)),
    get_conf(Path, N).

get_conf(DevPath, N) ->
    WildCard = io_lib:format("~s/dev/dev~b/~s/etc/*.conf", [DevPath, N, rtdev:which_riak(DevPath)]),
    [Conf] = filelib:wildcard(WildCard),
    Conf.

get_app_config(Node) ->
    N = node_id(Node),
    Path = relpath(node_version(N)),
    get_conf(Path, N).

get_app_config(DevPath, N) ->
    io_lib:format("~s/dev/dev~b/~s/etc/advanced.config", [DevPath, N, rtdev:which_riak(DevPath)]).

update_app_config(all, Config) ->
    [ update_app_config(DevPath, Config) || DevPath <- devpaths()];
update_app_config(Node, Config) when is_atom(Node) ->
    N = node_id(Node),
    Path = relpath(node_version(N)),
    FileFormatString = "~s/dev/dev~b/~s/etc/~s.config",

    AppConfigFile = io_lib:format(FileFormatString, [Path, N, rtdev:which_riak(Path), "app"]),
    AdvConfigFile = io_lib:format(FileFormatString, [Path, N, rtdev:which_riak(Path), "advanced"]),
    %% If there's an app.config, do it old style
    %% if not, use cuttlefish's adavnced.config
    case filelib:is_file(AppConfigFile) of
        true ->
            update_app_config_file(AppConfigFile, Config);
        _ ->
            update_app_config_file(AdvConfigFile, Config)
    end.

update_app_config_file(ConfigFile, Config) ->
    lager:debug("rtcs_dev:update_app_config_file(~s, ~s)", [ConfigFile, io_lib:format("\n~p\n", [Config])]),

    BaseConfig =
        case file:consult(ConfigFile) of
            {ok, [ValidConfig]} ->
                ValidConfig;
            {error, enoent} ->
                lager:warning("~s not found", [ConfigFile]),
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

%% Appropriate backend will be set by rtcs later.
get_backends() ->
    cs_multi_backend.

create_snmp_dirs(Nodes) ->
    Snmp = [node_path(Node) ++ "/data/snmp/agent/db" || Node <- Nodes],
    [?assertCmd("mkdir -p " ++ Dir) || Dir <- Snmp].

clean_data_dir(Nodes, SubDir) when is_list(Nodes) ->
    DataDirs = [node_path(Node) ++ "/data/" ++ SubDir || Node <- Nodes],
    lists:foreach(fun rm_dir/1, DataDirs).

rm_dir(Dir) ->
    lager:debug("Removing directory ~s", [Dir]),
    ?assertCmd("rm -rf " ++ Dir),
    ?assertEqual(false, filelib:is_dir(Dir)).

add_default_node_config(Nodes) ->
    case rt_config:get(rt_default_config, undefined) of
        undefined -> ok;
        Defaults when is_list(Defaults) ->
            rt:pmap(fun(Node) ->
                            update_app_config(Node, Defaults)
                    end, Nodes),
            ok;
        BadValue ->
            lager:error("Invalid value for rt_default_config : ~p", [BadValue]),
            throw({invalid_config, {rt_default_config, BadValue}})
    end.

clean_data_dir_all(DevPath) ->
    Devs = filelib:wildcard(DevPath ++ "/dev/*"),
    Clean = fun(C) ->
                    rm_dir(C ++ "/" ++ rtdev:which_riak(DevPath) ++ "/data")
            end,
    [Clean(D) || D <- Devs],
    ok.

clean_log_dir_all(DevPath) ->
    Devs = filelib:wildcard(DevPath ++ "/dev/*"),
    Clean = fun(C) ->
                    [] = os:cmd(io_lib:format("rm -rf ~s", [C ++ "/" ++ rtdev:which_riak(DevPath) ++ "/log/*"]))
            end,
    [Clean(D) || D <- Devs],
    ok.

stop(Node) ->
    stop(Node, current).
stop(Node, Vsn) ->
    Pid = rpc:call(Node, os, getpid, []),
    N = node_id(Node),
    lager:debug("Stopping ~s (id ~p, pid ~s, devpath ~p)", [Node, N, Pid, cluster_devpath(Node, Vsn)]),
    rtdev:run_riak(Node, cluster_devpath(Node, Vsn), "stop"),
    ok = rt:wait_until_unpingable(Node).

start(Node) ->
    start(Node, current).
start(Node, Vsn) ->
    rtdev:run_riak(Node, cluster_devpath(Node, Vsn), "start"),
    ok.

attach(Node, Expected) ->
    interactive(Node, "attach", Expected).

attach_direct(Node, Expected) ->
    interactive(Node, "attach-direct", Expected).

console(Node, Expected) ->
    interactive(Node, "console", Expected).

interactive(Node, Command, Exp) ->
    N = node_id(Node),
    Path = relpath(node_version(Node)),
    Cmd = rtdev:riakcmd(Path, N, Command),
    lager:info("Opening a port for riak ~s.", [Command]),
    lager:debug("Calling open_port with cmd ~s", [binary_to_list(iolist_to_binary(Cmd))]),
    P = open_port({spawn, binary_to_list(iolist_to_binary(Cmd))},
                  [stream, use_stdio, exit_status, binary, stderr_to_stdout]),
    interactive_loop(P, Exp).

interactive_loop(Port, Expected) ->
    receive
        {Port, {data, Data}} ->
            %% We've gotten some data, so the port isn't done executing
            %% Let's break it up by newline and display it.
            Tokens = string:tokens(binary_to_list(Data), "\n"),
            [lager:debug("~s", [Text]) || Text <- Tokens],

            %% Now we're going to take hd(Expected) which is either {expect, X}
            %% or {send, X}. If it's {expect, X}, we foldl through the Tokenized
            %% data looking for a partial match via rt:str/2. If we find one,
            %% we pop hd off the stack and continue iterating through the list
            %% with the next hd until we run out of input. Once hd is a tuple
            %% {send, X}, we send that test to the port. The assumption is that
            %% once we send data, anything else we still have in the buffer is
            %% meaningless, so we skip it. That's what that {sent, sent} thing
            %% is about. If there were a way to abort mid-foldl, I'd have done
            %% that. {sent, _} -> is just a pass through to get out of the fold.

            NewExpected = lists:foldl(fun(X, Expect) ->
                    [{Type, Text}|RemainingExpect] = case Expect of
                        [] -> [{done, "done"}|[]];
                        E -> E
                    end,
                    case {Type, rt:str(X, Text)} of
                        {expect, true} ->
                            RemainingExpect;
                        {expect, false} ->
                            [{Type, Text}|RemainingExpect];
                        {send, _} ->
                            port_command(Port, list_to_binary(Text ++ "\n")),
                            [{sent, "sent"}|RemainingExpect];
                        {sent, _} ->
                            Expect;
                        {done, _} ->
                            []
                    end
                end, Expected, Tokens),
            %% Now that the fold is over, we should remove {sent, sent} if it's there.
            %% The fold might have ended not matching anything or not sending anything
            %% so it's possible we don't have to remove {sent, sent}. This will be passed
            %% to interactive_loop's next iteration.
            NewerExpected = case NewExpected of
                [{sent, "sent"}|E] -> E;
                E -> E
            end,
            %% If NewerExpected is empty, we've met all expected criteria and in order to boot
            %% Otherwise, loop.
            case NewerExpected of
                [] -> ?assert(true);
                _ -> interactive_loop(Port, NewerExpected)
            end;
        {Port, {exit_status,_}} ->
            %% This port has exited. Maybe the last thing we did was {send, [4]} which
            %% as Ctrl-D would have exited the console. If Expected is empty, then
            %% We've met every expectation. Yay! If not, it means we've exited before
            %% something expected happened.
            ?assertEqual([], Expected)
        after rt_config:get(rt_max_wait_time) ->
            %% interactive_loop is going to wait until it matches expected behavior
            %% If it doesn't, the test should fail; however, without a timeout it
            %% will just hang forever in search of expected behavior. See also: Parenting
            ?assertEqual([], Expected)
    end.

admin(Node, Args, Options) ->
    N = node_id(Node),
    Path = relpath(node_version(N)),
    Cmd = rtdev:riak_admin_cmd(Path, N, Args),
    lager:info("Running: ~s", [Cmd]),
    Result = execute_admin_cmd(Cmd, Options),
    lager:info("~s", [Result]),
    {ok, Result}.

execute_admin_cmd(Cmd, Options) ->
    {_ExitCode, Result} = FullResult = wait_for_cmd(spawn_cmd(Cmd)),
    case lists:member(return_exit_code, Options) of
        true ->
            FullResult;
        false ->
            Result
    end.

node_id(Node) ->
    NodeMap = rt_config:get(rt_nodes),
    orddict:fetch(Node, NodeMap).

node_version(N) ->
    VersionMap = rt_config:get(rt_versions),
    orddict:fetch(N, VersionMap).

spawn_cmd(Cmd) ->
    spawn_cmd(Cmd, []).
spawn_cmd(Cmd, Opts) ->
    open_port({spawn, Cmd}, [stream, in, exit_status, stderr_to_stdout] ++ Opts).

wait_for_cmd(Port) ->
    rt:wait_until(node(),
                  fun(_) ->
                          receive
                              {Port, Msg={data, _}} ->
                                  self() ! {Port, Msg},
                                  false;
                              {Port, Msg={exit_status, _}} ->
                                  catch port_close(Port),
                                  self() ! {Port, Msg},
                                  true
                          after 0 ->
                                  false
                          end
                  end),
    get_cmd_result(Port, []).

cmd(Cmd) ->
    cmd(Cmd, []).

cmd(Cmd, Opts) ->
    wait_for_cmd(spawn_cmd(Cmd, Opts)).

get_cmd_result(Port, Acc) ->
    receive
        {Port, {data, Bytes}} ->
            get_cmd_result(Port, [Bytes|Acc]);
        {Port, {exit_status, Status}} ->
            Output = lists:flatten(lists:reverse(Acc)),
            {Status, Output}
    after 0 ->
            timeout
    end.

check_node({_N, Version}) ->
    case proplists:is_defined(Version, rt_config:get(build_paths)) of
        true -> ok;
        _ ->
            lager:error("You don't have Riak ~s installed or configured", [Version]),
            erlang:error("You don't have Riak " ++ atom_to_list(Version) ++ " installed or configured")
    end.

set_backend(Backend) ->
    lager:debug("rtcs_dev:set_backend(~p)", [Backend]),
    update_app_config(all, [{riak_kv, [{storage_backend, Backend}]}]),
    get_backends().

get_version() ->
    case file:read_file(relpath(cs_current) ++ "/VERSION") of
        {error, enoent} -> unknown;
        {ok, Version} -> Version
    end.

teardown() ->
    ok.

ensure_riak_last(DevPaths) ->
    lists:sort(fun(P1, P2) ->
                       case {rtdev:which_riak(P1), rtdev:which_riak(P2)} of
                           {"riak", Other} when Other /= "riak" ->
                               false;
                           _ ->
                               true
                       end
               end, DevPaths).


whats_up() ->
    io:format("Here's what's running...~n"),

    Up = [rpc:call(Node, os, cmd, ["pwd"]) || Node <- nodes()],
    [io:format("  ~s~n",[string:substr(Dir, 1, length(Dir)-1)]) || Dir <- Up].

devpaths() ->
    lists:usort([ DevPath || {Name, DevPath} <- rt_config:get(build_paths),
                             not lists:member(Name, [root, ee_root, cs_root, stanchion_root])
                ]).

all_the_files(DevPath, File) ->
    case rtdev:which_riak(DevPath) of
        "stanchion" ->
            filelib:wildcard(io_lib:format("~s/dev/stanchion/~s", [DevPath, File]));
        A ->
            filelib:wildcard(io_lib:format("~s/dev/dev?/~s/~s", [DevPath, A, File]))
    end.

devpath(Name, Vsn) ->
    rtcs_config:devpath(Name, Vsn).

cluster_devpath(Node) ->
    cluster_devpath(Node, current).
cluster_devpath(Node, Vsn) ->
    case atom_to_binary(Node, latin1) of
        <<"dev", _/binary>> ->
            devpath(riak, Vsn);
        <<"rcs-dev", _/binary>> ->
            devpath(cs, Vsn);
        <<"stanchion", _/binary>> ->
            devpath(stanchion, Vsn)
    end.

node_path(Node) ->
    node_path(Node, current).
node_path(Node, Vsn)
  when is_atom(Node) andalso (Vsn == current orelse Vsn == previous) ->
    ClusterDevpath = cluster_devpath(Node, Vsn),
    case rtdev:which_riak(ClusterDevpath) of
        "stanchion" ->
            io_lib:format("~s/dev/stanchion", [ClusterDevpath]);
        WhichRiak ->
            io_lib:format("~s/dev/dev~b/~s", [ClusterDevpath, node_id(Node), WhichRiak])
    end.

versions() ->
    proplists:get_keys(rt_config:get(build_paths)) -- [root].

get_node_logs() ->
    lists:flatmap(fun get_node_logs/1, [root, ee_root, cs_root, stanchion_root]).

get_node_logs(Base) ->
    Root = filename:absname(proplists:get_value(Base, ?BUILD_PATHS)),
    %% Unlike Riak, Riak CS has multiple things in the root and so we need
    %% to distinguish between them.
    RootLen = length(filename:dirname(Root)) + 1, %% Remove the leading slash
    [ begin
          {ok, Port} = file:open(Filename, [read, binary]),
          {lists:nthtail(RootLen, Filename), Port}
      end || Filename <- filelib:wildcard(Root ++ "/*/dev/dev*/riak-cs/log/*") ].


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
                           lager:info("found existing backup of ~s; restoring it", [F]),
                           [] = os:cmd(io_lib:format("cp -a \"~s.backup\" \"~s\"", [F, F]));
                       false ->
                           lager:debug("backing up ~s", [F]),
                           [] = os:cmd(io_lib:format("cp -a \"~s\" \"~s.backup\"", [F, F]))
                   end
               end || F <- [ConfFile, AdvCfgFile]]
      end,
      Nodes).

%% create_data_dir_backups(Nodes, Vsn) ->
%%     lists:foreach(
%%       fun(Node) ->
%%               NodePath = node_path(Node, Vsn),
%%               [begin
%%                    Dir = io_lib:format("~s/data/~s", [NodePath, Item]),
%%                    case filelib:is_dir(Dir ++ ".backup") of
%%                        true ->
%%                            lager:warning("not overwriting existing backup of ~s", [Dir]);
%%                        false ->
%%                            case filelib:is_dir(Dir) of
%%                                true ->
%%                                    lager:info("backing up ~s", [Dir]),
%%                                    os:cmd(io_lib:format("cp -a \"~s\" \"~s.backup\"", [Dir, Dir]));
%%                                false ->
%%                                    lager:info("creating empty ~s", [Dir]),
%%                                    os:cmd(io_lib:format("mkdir \"~s.backup\"", [Dir]))
%%                            end
%%                    end
%%                end || Item <- ["bitcask", "leveldb", "ring"]]
%%       end,
%%       Nodes).


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
                           lager:info("backup of ~s not found", [F]);
                       true ->
                           lager:debug("restoring ~s", [F]),
                           [] = os:cmd(io_lib:format("mv -f \"~s.backup\" \"~s\"", [F, F]))
                   end
               end || F <- [ConfFile, AdvCfgFile]]
      end,
      Nodes).


%% restore_data_dirs(Nodes, Vsn) ->
%%     lists:foreach(
%%       fun(Node) ->
%%               NodePath = node_path(Node, Vsn),
%%               [begin
%%                    Dir = io_lib:format("~s/data/~s", [NodePath, Item]),
%%                    case filelib:is_dir(Dir ++ ".backup") of
%%                        false ->
%%                            lager:warning("backup of ~s not found", [Dir]);
%%                        true ->
%%                            lager:info("restoring ~s", [Dir]),
%%                            [] = os:cmd(io_lib:format("rm -rf \"~s\"", [Dir])),
%%                            [] = os:cmd(io_lib:format("mv \"~s.backup\" \"~s\"", [Dir, Dir]))
%%                    end
%%                end || Item <- ["bitcask", "leveldb", "ring"]]
%%       end,
%%       Nodes).

load_cs_modules_for_riak_pipe_fittings(CSNode, RiakNodes, Mods) ->
    ExtPath = filename:dirname(rpc:call(CSNode, code, which, [riak_cs_storage])),
    lists:foreach(
      fun(N) ->
              rpc:call(N, code, add_pathz, [ExtPath]),
              lists:foreach(
                fun(M) -> {module, _} = rpc:call(N, code, load_file, [M]) end,
                Mods)
      end, RiakNodes).
