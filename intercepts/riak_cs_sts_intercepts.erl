-module(riak_cs_sts_intercepts).

-export([validate_duration_seconds_permissive/1]).

-include("intercept.hrl").

validate_duration_seconds_permissive(_) ->
    ok.
