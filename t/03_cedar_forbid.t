use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_shuffle();
no_root_location();

run_tests();

__DATA__

=== TEST 1: forbid priority - permit all but forbid DELETE (GET allowed)
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/forbid_priority.cedar;
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


=== TEST 2: forbid priority - DELETE denied even with permit all
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/forbid_priority.cedar;
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


=== TEST 3: forbid priority - POST allowed (405 = passed precontent phase)
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/forbid_priority.cedar;
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


=== TEST 4: basic forbid - GET allowed
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/basic_forbid.cedar;
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


=== TEST 5: basic forbid - DELETE denied
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/basic_forbid.cedar;
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
