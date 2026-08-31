use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_shuffle();
no_root_location();

run_tests();

__DATA__

=== TEST 1: cedar ALLOW lets a later PRECONTENT-phase handler (try_files)
            run — the requested file is missing, so only try_files's
            fallback can produce a 200
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/basic_permit.cedar;
--- config
    location /order.html {
        auth_cedar on;
        try_files $uri /fallback.html;
    }
--- user_files
>>> fallback.html
FALLBACK
--- request
GET /order.html
--- error_code: 200
--- response_body
FALLBACK


=== TEST 2: cedar DENY still short-circuits before try_files runs (deny
            path is unaffected by the ALLOW-path fix)
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/default_deny.cedar;
--- config
    location /order2.html {
        auth_cedar on;
        try_files $uri /fallback2.html;
    }
--- user_files
>>> fallback2.html
FALLBACK2
--- request
GET /order2.html
--- error_code: 403
