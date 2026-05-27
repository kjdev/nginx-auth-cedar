use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_shuffle();
no_root_location();

run_tests();

__DATA__

=== TEST 1: auth_cedar_deny_status 400 - lower bound accepted
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/default_deny.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_deny_status 400;
    }
--- request
GET /test.html
--- error_code: 400


=== TEST 2: auth_cedar_deny_status 599 - upper bound accepted
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/default_deny.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_deny_status 599;
    }
--- request
GET /test.html
--- error_code: 599


=== TEST 3: auth_cedar_deny_status 399 - below 4xx rejected at config time
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/default_deny.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_deny_status 399;
    }
--- must_die
--- error_log
invalid status code "399"


=== TEST 4: auth_cedar_deny_status 600 - above 5xx rejected at config time
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/default_deny.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_deny_status 600;
    }
--- must_die
--- error_log
invalid status code "600"


=== TEST 5: auth_cedar_deny_status absent - default is 403
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/default_deny.cedar;
--- config
    location /test.html {
        auth_cedar on;
    }
--- request
GET /test.html
--- error_code: 403
