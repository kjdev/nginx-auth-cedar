use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_shuffle();
no_root_location();

run_tests();

__DATA__

=== TEST 1: $cedar_result - allow
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/basic_permit.cedar;
--- config
    location /test.html {
        auth_cedar on;
        add_header X-Cedar-Result $cedar_result;
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 200
--- response_headers
X-Cedar-Result: allow


=== TEST 2: $cedar_decision - allow (1)
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/basic_permit.cedar;
--- config
    location /test.html {
        auth_cedar on;
        add_header X-Cedar-Decision $cedar_decision;
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 200
--- response_headers
X-Cedar-Decision: 1


=== TEST 3: $cedar_result - deny
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/default_deny.cedar;
--- config
    location /test.html {
        auth_cedar on;
        add_header X-Cedar-Result $cedar_result always;
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 403
--- response_headers
X-Cedar-Result: deny


=== TEST 4: $cedar_decision - deny (0)
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/default_deny.cedar;
--- config
    location /test.html {
        auth_cedar on;
        add_header X-Cedar-Decision $cedar_decision always;
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 403
--- response_headers
X-Cedar-Decision: 0


=== TEST 5: $cedar_result - not evaluated (auth_cedar off)
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/basic_permit.cedar;
--- config
    location /test.html {
        auth_cedar off;
        add_header X-Cedar-Result $cedar_result;
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 200
--- response_headers
! X-Cedar-Result


=== TEST 6: $cedar_decision - not evaluated (auth_cedar off)
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/basic_permit.cedar;
--- config
    location /test.html {
        auth_cedar off;
        add_header X-Cedar-Decision $cedar_decision;
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 200
--- response_headers
! X-Cedar-Decision


=== TEST 7: $cedar_result in log format
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/basic_permit.cedar;
    log_format cedar '$request_method $uri cedar_result=$cedar_result';
--- config
    location /test.html {
        auth_cedar on;
        access_log logs/cedar_access.log cedar;
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 200
--- no_error_log
[error]
