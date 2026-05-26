use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_shuffle();
no_root_location();

run_tests();

__DATA__

=== TEST 1: auth_cedar_principal_id - literal matches the policy
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/principal_id_match.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_id "alice";
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 200
--- response_body
OK


=== TEST 2: auth_cedar_principal_id - literal mismatch denies
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/principal_id_match.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_id "bob";
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 403


=== TEST 3: auth_cedar_principal_id - sourced from a request header variable
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/principal_id_match.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_id $http_x_principal;
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- more_headers
X-Principal: alice
--- error_code: 200
--- response_body
OK


=== TEST 4: auth_cedar_principal_id - empty variable falls through to deny
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/principal_id_match.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_id $http_x_principal;
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 403


=== TEST 5: principal_id is inherited from server to location
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/principal_id_match.cedar;
--- config
    auth_cedar_principal_id "alice";
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


=== TEST 6: location-level principal_id overrides server-level
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/principal_id_match.cedar;
--- config
    auth_cedar_principal_id "alice";
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_id "bob";
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 403


=== TEST 7: deny log reports the resolved principal id, not
            $remote_user (which auth_cedar_principal_id replaces)
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/principal_id_match.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_id $http_x_principal;
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- more_headers
X-Principal: mallory
--- error_code: 403
--- error_log
principal="mallory"
