use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_shuffle();
no_root_location();

run_tests();

__DATA__

=== TEST 1: `has` - role header present, admin allowed
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/acc_has.cedar;
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


=== TEST 2: `has` - role header missing, denied (no attribute → short-circuit false)
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/acc_has.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_attr role $http_x_role;
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 403


=== TEST 3: `is` (expression) - principal is User (type fixed by module)
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/acc_is.cedar;
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


=== TEST 4: `is` (scope) - principal is User in scope position
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/acc_is_scope.cedar;
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


=== TEST 5: bracket access - principal["role"] == "admin"
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/acc_bracket.cedar;
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


=== TEST 6: bracket access - dashed key from context attribute
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/acc_bracket_dashed.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_context_attr x-real-ip $http_x_real_ip;
    }
--- user_files
>>> test.html
OK
--- more_headers
X-Real-IP: 10.0.0.1
--- request
GET /test.html
--- error_code: 200


=== TEST 7: bracket access - dashed key mismatch denies
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/acc_bracket_dashed.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_context_attr x-real-ip $http_x_real_ip;
    }
--- user_files
>>> test.html
OK
--- more_headers
X-Real-IP: 192.168.1.1
--- request
GET /test.html
--- error_code: 403


=== TEST 8: record literal `{...}.field` access
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/acc_record.cedar;
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


=== TEST 9: set methods - .contains / .containsAll / .containsAny
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/acc_set_contains.cedar;
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


=== TEST 10: set method - .contains rejects unknown role
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/acc_set_contains.cedar;
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


=== TEST 11: set method - .isEmpty() on empty and non-empty set
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/acc_set_isempty.cedar;
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


=== TEST 12: if-then-else - admin role matches then-branch
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/acc_if_then_else.cedar;
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


=== TEST 13: if-then-else - manager role matches else-branch
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/acc_if_then_else.cedar;
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


=== TEST 14: if-then-else - else-branch rejects unknown role
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/acc_if_then_else.cedar;
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
