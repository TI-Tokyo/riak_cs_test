%% riak_test in riak_cs-2.1 used an old, forked version of erlcloud,
%% with erlcloud_s3:s3_request/9 customized and made exportable. That
%% version, https://github.com/basho/erlcloud/releases/tag/0.4.6,
%% could not be (easily) built in otp-22, so here's a record,
%% #aws_config, used by some functions manually imported from it.
%% manually copied from it.

-record(rtcs_aws_config, {
          ec2_host="ec2.amazonaws.com"::string(),
          s3_host="s3.amazonaws.com"::string(),
          s3_port=80::non_neg_integer(),
          s3_prot="https"::string(),
          sdb_host="sdb.amazonaws.com"::string(),
          elb_host="elasticloadbalancing.amazonaws.com"::string(),
          sqs_host="queue.amazonaws.com"::string(),
          mturk_host="mechanicalturk.amazonaws.com"::string(),
          mon_host="monitoring.amazonaws.com"::string(),
          access_key_id::string(),
          secret_access_key::string(),
          http_options=[]::proplists:proplist()
}).

-type(rtcs_aws_config() :: #rtcs_aws_config{}).
