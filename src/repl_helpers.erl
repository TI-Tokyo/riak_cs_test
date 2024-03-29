-module(repl_helpers).
-compile(export_all).
-compile(nowarn_export_all).
-include_lib("eunit/include/eunit.hrl").

verify_sites_balanced(NumSites, BNodes0) ->
    rt:wait_until(fun() ->
                          L = rpc:call(hd(BNodes0), riak_repl_leader, leader_node, []),
                          L =/= undefined
                  end),
    Leader = rpc:call(hd(BNodes0), riak_repl_leader, leader_node, []),
    case node_has_version(Leader, "1.2.0") of
        true ->
            BNodes = nodes_with_version(BNodes0, "1.2.0") -- [Leader],
            NumNodes = length(BNodes),
            case NumNodes of
                0 ->
                    %% only leader is upgraded, runs clients locally
                    ?assertEqual(NumSites, client_count(Leader));
                _ ->
                    NodeCounts = [{Node, client_count(Node)} || Node <- BNodes],
                    logger:notice("nodecounts ~p", [NodeCounts]),
                    logger:notice("leader ~p", [Leader]),
                    Min = NumSites div NumNodes,
                    [?assert(Count >= Min) || {_Node, Count} <- NodeCounts]
            end;
        false ->
            ok
    end.

%% does the node meet the version requirement?
node_has_version(Node, Version) ->
    NodeVersion =  rtdev:node_version(rtdev:node_id(Node)),
    case NodeVersion of
        current ->
            %% current always satisfies any version check
            true;
        _ ->
            NodeVersion >= Version
    end.

nodes_with_version(Nodes, Version) ->
    [Node || Node <- Nodes, node_has_version(Node, Version)].

client_count(Node) ->
    Clients = rpc:call(Node, supervisor, which_children, [riak_repl_client_sup]),
    length(Clients).

add_site(Node, {IP, Port, Name}) ->
    logger:info("Add site ~p ~p:~p at node ~p", [Name, IP, Port, Node]),
    Args = [IP, integer_to_list(Port), Name],
    Res = rpc:call(Node, riak_repl_console, add_site, [Args]),
    ?assertEqual(ok, Res).

del_site(Node, Name) ->
    logger:info("Del site ~p at ~p", [Name, Node]),
    Res = rpc:call(Node, riak_repl_console, del_site, [[Name]]),
    ?assertEqual(ok, Res).

verify_listeners(Listeners) ->
    Strs = [IP ++ ":" ++ integer_to_list(Port) || {IP, Port, _} <- Listeners],
    [?assertEqual(ok, verify_listener(Node, Strs)) || {_, _, Node} <- Listeners].

verify_listener(Node, Strs) ->
    logger:info("Verify listeners ~p ~p", [Node, Strs]),
    rt:wait_until(Node,
        fun(_) ->
                Status = rpc:call(Node, riak_repl_console, status, [quiet]),
                lists:all(fun(Str) ->
                            lists:keymember(Str, 2, Status)
                    end, Strs)
        end).

add_listeners(Nodes=[FirstNode|_]) ->
    Ports = gen_ports(9010, length(Nodes)),
    IPs = lists:duplicate(length(Nodes), "127.0.0.1"),
    PN = lists:zip3(IPs, Ports, Nodes),
    [add_listener(FirstNode, Node, IP, Port) || {IP, Port, Node} <- PN],
    PN.

add_listener(N, Node, IP, Port) ->
    logger:info("Adding repl listener to ~p ~s:~p", [Node, IP, Port]),
    Args = [[atom_to_list(Node), IP, integer_to_list(Port)]],
    Res = rpc:call(N, riak_repl_console, add_listener, Args),
    ?assertEqual(ok, Res).

gen_ports(Start, Len) ->
    lists:seq(Start, Start + Len - 1).

verify_site_ips(Leader, Site, Listeners) ->
    rt:wait_until(
      fun() -> Status = rpc:call(Leader, riak_repl_console, status, [quiet]),
               Key = lists:flatten([Site, "_ips"]),
               IPStr = proplists:get_value(Key, Status),
               IPs = lists:sort(re:split(IPStr, ", ")),
               ExpectedIPs = lists:sort(
                               [list_to_binary([IP, ":", integer_to_list(Port)]) ||
                                   {IP, Port, _Node} <- Listeners]),
               ExpectedIPs =:= IPs
      end).

start_and_wait_until_fullsync_complete(Node) ->
    Status0 = rpc:call(Node, riak_repl_console, status, [quiet]),
    Count = proplists:get_value(server_fullsyncs, Status0) + 1,
    logger:info("waiting for fullsync count to be ~p", [Count]),

    logger:info("Starting fullsync on ~p (~p)", [Node,
            rtdev:node_version(rtdev:node_id(Node))]),
    rpc:call(Node, riak_repl_console, start_fullsync, [[]]),
    %% sleep because of the old bug where stats will crash if you call it too
    %% soon after starting a fullsync
    timer:sleep(500),

    Res = rt:wait_until(Node,
        fun(_) ->
                Status = rpc:call(Node, riak_repl_console, status, [quiet]),
                case proplists:get_value(server_fullsyncs, Status) of
                    C when C >= Count ->
                        true;
                    _ ->
                        false
                end
        end),
    case node_has_version(Node, "1.2.0") of
        true ->
            ?assertEqual(ok, Res);
        _ ->
            case Res of
                ok ->
                    ok;
                _ ->
                    ?assertEqual(ok, wait_until_connection(Node)),
                    logger:warning("Pre 1.2.0 node failed to fullsync, retrying"),
                    start_and_wait_until_fullsync_complete(Node)
            end
    end,

    logger:info("Fullsync on ~p complete", [Node]).


wait_until_leader(Node) ->
    Res = rt:wait_until(Node,
        fun(_) ->
                Status = rpc:call(Node, riak_repl_console, status, [quiet]),
                case Status of
                    {badrpc, _} ->
                        false;
                    _ ->
                        case proplists:get_value(leader, Status) of
                            undefined ->
                                false;
                            _ ->
                                true
                        end
                end
        end),
    ?assertEqual(ok, Res).


wait_until_13_leader(Node) ->
    wait_until_new_leader(Node, undefined).

%% taken from
%% https://github.com/basho/riak_test/blob/master/tests/repl_util.erl
wait_until_new_leader(Node, OldLeader) ->
    Res = rt:wait_until(Node,
        fun(_) ->
                Status = rpc:call(Node, riak_core_cluster_mgr, get_leader, []),
                case Status of
                    {badrpc, _} ->
                        false;
                    undefined ->
                        false;
                    OldLeader ->
                        false;
                    _Other ->
                        true
                end
        end),
    ?assertEqual(ok, Res).

wait_until_leader_converge([Node|_] = Nodes) ->
    rt:wait_until(Node,
        fun(_) ->
                length(lists:usort([begin
                        case rpc:call(N, riak_core_cluster_mgr, get_leader, []) of
                            undefined ->
                                false;
                            L ->
                                %logger:info("Leader for ~p is ~p",
                                %[N,L]),
                                L
                        end
                end || N <- Nodes])) == 1
        end).

wait_until_connection(Node) ->
    rt:wait_until(Node,
        fun(_) ->
                Status = rpc:call(Node, riak_repl_console, status, [quiet]),
                case proplists:get_value(server_stats, Status) of
                    [] ->
                        false;
                    [_C] ->
                        true;
                    Conns ->
                        logger:warning("multiple connections detected: ~p",
                            [Conns]),
                        true
                end
        end, 80, 500). %% 40 seconds is enough for repl

%% The functions below are for 1.3 repl (aka Advanced Mode MDC)
connect_cluster(Node, IP, Port) ->
    Res = rpc:call(Node, riak_repl_console, connect,
        [[IP, integer_to_list(Port)]]),
    ?assertEqual(ok, Res).

disconnect_cluster(Node, Name) ->
    Res = rpc:call(Node, riak_repl_console, disconnect,
        [[Name]]),
    ?assertEqual(ok, Res).

wait_for_connection(Node, Name) ->
    rt:wait_until(Node,
        fun(_) ->
                {ok, Connections} = rpc:call(Node, riak_core_cluster_mgr,
                    get_connections, []),
                lists:any(fun({{cluster_by_name, N}, _}) when N == Name -> true;
                        (_) -> false
                    end, Connections)
        end).

wait_until_no_connection(Node) ->
    rt:wait_until(Node,
        fun(_) ->
                Status = rpc:call(Node, riak_repl_console, status, [quiet]),
                case proplists:get_value(connected_clusters, Status) of
                    [] ->
                        true;
                    _ ->
                        false
                end
        end). %% 40 seconds is enough for repl

enable_realtime(Node, Cluster) ->
    Res = rpc:call(Node, riak_repl_console, realtime, [["enable", Cluster]]),
    ?assertEqual(ok, Res).

disable_realtime(Node, Cluster) ->
    Res = rpc:call(Node, riak_repl_console, realtime, [["disable", Cluster]]),
    ?assertEqual(ok, Res).

enable_fullsync(Node, Cluster) ->
    Res = rpc:call(Node, riak_repl_console, fullsync, [["enable", Cluster]]),
    ?assertEqual(ok, Res).

start_realtime(Node, Cluster) ->
    Res = rpc:call(Node, riak_repl_console, realtime, [["start", Cluster]]),
    ?assertEqual(ok, Res).

stop_realtime(Node, Cluster) ->
    Res = rpc:call(Node, riak_repl_console, realtime, [["stop", Cluster]]),
    ?assertEqual(ok, Res).

name_cluster(Node, Name) ->
    logger:info("Naming cluster ~p",[Name]),
    Res = rpc:call(Node, riak_repl_console, clustername, [[Name]]),
    ?assertEqual(ok, Res).

connect_clusters13(LeaderA, ANodes, BPort, Name) ->
    logger:info("Connecting to ~p", [Name]),
    connect_cluster13(LeaderA, "127.0.0.1", BPort),
    ?assertEqual(ok, wait_for_connection13(LeaderA, Name)),
    enable_realtime(LeaderA, Name),
    rt:wait_until_ring_converged(ANodes),
    start_realtime(LeaderA, Name),
    rt:wait_until_ring_converged(ANodes),
    enable_fullsync(LeaderA, Name),
    rt:wait_until_ring_converged(ANodes),
    ?assertEqual(ok, wait_for_connection13(LeaderA, Name)),
    rt:wait_until_ring_converged(ANodes).

disconnect_clusters13(LeaderA, ANodes, Name) ->
    logger:info("Disconnecting from ~p", [Name]),
    disconnect_cluster13(LeaderA, Name),
    disable_realtime(LeaderA, Name),
    rt:wait_until_ring_converged(ANodes),
    stop_realtime(LeaderA, Name),
    rt:wait_until_ring_converged(ANodes),
    ?assertEqual(ok, wait_until_no_connection13(LeaderA)),
    rt:wait_until_ring_converged(ANodes).

start_and_wait_until_fullsync_complete13(Node) ->
    Status0 = rpc:call(Node, riak_repl_console, status, [quiet]),
    Count = proplists:get_value(server_fullsyncs, Status0) + 1,
    logger:info("waiting for fullsync count to be ~p", [Count]),

    logger:info("Starting fullsync on ~p (~p)", [Node,
            rtdev:node_version(rtdev:node_id(Node))]),
    rpc:call(Node, riak_repl_console, fullsync, [["start"]]),
    %% sleep because of the old bug where stats will crash if you call it too
    %% soon after starting a fullsync
    timer:sleep(500),

    Res = rt:wait_until(Node,
        fun(_) ->
                Status = rpc:call(Node, riak_repl_console, status, [quiet]),
                case proplists:get_value(server_fullsyncs, Status) of
                    C when C >= Count ->
                        true;
                    _ ->
                        false
                end
        end),
    ?assertEqual(ok, Res),

    logger:info("Fullsync on ~p complete", [Node]).

wait_for_connection13(Node, Name) ->
    rt:wait_until(Node,
        fun(_) ->
                {ok, Connections} = rpc:call(Node, riak_core_cluster_mgr,
                    get_connections, []),
                lists:any(fun({{cluster_by_name, N}, _}) when N == Name -> true;
                        (_) -> false
                    end, Connections)
        end).

wait_until_no_connection13(Node) ->
    rt:wait_until(Node,
        fun(_) ->
                Status = rpc:call(Node, riak_repl_console, status, [quiet]),
                case proplists:get_value(connected_clusters, Status) of
                    [] ->
                        true;
                    _ ->
                        false
                end
        end). %% 40 seconds is enough for repl

wait_until_realtime_sync_complete(Nodes) ->
    [wait_until_rtq_drained(Node)||Node <- Nodes].

wait_until_rtq_drained(Node) ->
    rt:wait_until(Node,
        fun(_) ->
                case rpc:call(Node, riak_repl2_rtq, dumpq, []) of
                    [] ->
                        true;
                    _ ->
                        false
                end
        end),
    logger:info("Realtime sync on ~p complete", [Node]).

connect_cluster13(Node, IP, Port) ->
    Res = rpc:call(Node, riak_repl_console, connect,
        [[IP, integer_to_list(Port)]]),
    ?assertEqual(ok, Res).

disconnect_cluster13(Node, Name) ->
    Res = rpc:call(Node, riak_repl_console, disconnect,
        [[Name]]),
    ?assertEqual(ok, Res).

enable_pg13(Node, Cluster) ->
    Res = rpc:call(Node, riak_repl_console, proxy_get, [["enable", Cluster]]),
    ?assertEqual(ok, Res).

disable_pg13(Node, Cluster) ->
    Res = rpc:call(Node, riak_repl_console, proxy_get, [["disable", Cluster]]),
    ?assertEqual(ok, Res).
