use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_shuffle();
no_root_location();

run_tests();

__DATA__

=== TEST 1: permit GET - allowed
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/basic_permit.cedar;
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


=== TEST 2: permit GET - POST denied (no matching permit)
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/basic_permit.cedar;
--- config
    location /test.html {
        auth_cedar on;
    }
--- user_files
>>> test.html
OK
--- request
POST /test.html
--- error_code: 403


=== TEST 3: multi action set - GET allowed
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/multi_action.cedar;
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


=== TEST 4: multi action set - POST allowed (405 = passed precontent phase)
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/multi_action.cedar;
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


=== TEST 5: multi action set - DELETE denied
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/multi_action.cedar;
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
