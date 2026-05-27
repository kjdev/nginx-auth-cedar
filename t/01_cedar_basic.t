use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_shuffle();
no_root_location();

run_tests();

__DATA__

=== TEST 1: auth_cedar on - basic permit GET
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/basic_permit.cedar;
--- config
    location /test.html {
        auth_cedar on;
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 200
--- response_body
OK
--- no_error_log
[error]


=== TEST 2: auth_cedar off - skip authorization
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/default_deny.cedar;
--- config
    location /test.html {
        auth_cedar off;
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 200
--- response_body
OK
--- no_error_log
[error]


=== TEST 3: default deny - no permit policy matches GET
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/default_deny.cedar;
--- config
    location /test.html {
        auth_cedar on;
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 403


=== TEST 4: empty policy file - default deny
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/empty.cedar;
--- config
    location /test.html {
        auth_cedar on;
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 403


=== TEST 5: multiple policy files - merged (GET from file1, POST from file2)
--- http_config
    auth_cedar_policy_file def
        $TEST_NGINX_CONF_DIR/policies/basic_permit.cedar
        $TEST_NGINX_CONF_DIR/policies/permit_post.cedar;
--- config
    location /test.html {
        auth_cedar on;
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 200
--- response_body
OK


=== TEST 6: multiple policy files - POST allowed from second file (405 = passed precontent)
--- http_config
    auth_cedar_policy_file def
        $TEST_NGINX_CONF_DIR/policies/basic_permit.cedar
        $TEST_NGINX_CONF_DIR/policies/permit_post.cedar;
--- config
    location /test.html {
        auth_cedar on;
    }
--- user_files
>>> test.html
OK
--- request
POST /test.html
--- error_code: 405


=== TEST 7: multiple policy files - DELETE denied (no permit in either file)
--- http_config
    auth_cedar_policy_file def
        $TEST_NGINX_CONF_DIR/policies/basic_permit.cedar
        $TEST_NGINX_CONF_DIR/policies/permit_post.cedar;
--- config
    location /test.html {
        auth_cedar on;
    }
--- user_files
>>> test.html
OK
--- request
DELETE /test.html
--- error_code: 403


=== TEST 8: auth_cedar not set (default off) - skip authorization
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/default_deny.cedar;
--- config
    location /test.html {
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 200
--- response_body
OK
--- no_error_log
[error]
