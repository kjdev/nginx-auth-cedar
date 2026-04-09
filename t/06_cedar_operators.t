use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_shuffle();
no_root_location();

run_tests();

__DATA__

=== TEST 1: `!=` - principal.role != "guest" (admin allowed)
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/op_neq.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_attr role $http_x_role;
    }
--- user_files
>>> test.html
OK
--- more_headers
X-Role: admin
--- request
GET /test.html
--- error_code: 200


=== TEST 2: `!=` - principal.role != "guest" (guest denied)
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/op_neq.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_attr role $http_x_role;
    }
--- user_files
>>> test.html
OK
--- more_headers
X-Role: guest
--- request
GET /test.html
--- error_code: 403


=== TEST 3: `<` true - 1 < 2 permits all
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/op_lt.cedar;
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


=== TEST 4: `<` false - 2 < 1 denies (default deny)
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/op_lt_false.cedar;
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


=== TEST 5: `<=` boundary and strict cases both true
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/op_le.cedar;
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


=== TEST 6: `>` true - 5 > 3 permits
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/op_gt.cedar;
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


=== TEST 7: `>=` boundary and strict cases both true
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/op_ge.cedar;
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


=== TEST 8: `&&` / `||` - admin allowed
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/op_and_or.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_attr role $http_x_role;
    }
--- user_files
>>> test.html
OK
--- more_headers
X-Role: admin
--- request
GET /test.html
--- error_code: 200


=== TEST 9: `&&` / `||` - manager allowed
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/op_and_or.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_attr role $http_x_role;
    }
--- user_files
>>> test.html
OK
--- more_headers
X-Role: manager
--- request
GET /test.html
--- error_code: 200


=== TEST 10: `&&` / `||` - other role denied
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/op_and_or.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_attr role $http_x_role;
    }
--- user_files
>>> test.html
OK
--- more_headers
X-Role: user
--- request
GET /test.html
--- error_code: 403


=== TEST 11: `!` negation - non-guest allowed
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/op_not.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_attr role $http_x_role;
    }
--- user_files
>>> test.html
OK
--- more_headers
X-Role: admin
--- request
GET /test.html
--- error_code: 200


=== TEST 12: `!` negation - guest denied
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/op_not.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_attr role $http_x_role;
    }
--- user_files
>>> test.html
OK
--- more_headers
X-Role: guest
--- request
GET /test.html
--- error_code: 403


=== TEST 13: arithmetic operators - +, -, *, unary - all correct
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/op_arith.cedar;
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
