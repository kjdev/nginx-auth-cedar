use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_shuffle();
no_root_location();

run_tests();

__DATA__

=== TEST 1: eval error - String + Long type mismatch denies (permit skipped)
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/err_type_mismatch.cedar;
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
--- error_code: 403


=== TEST 2: eval error - Long arithmetic overflow denies (permit skipped)
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/err_overflow.cedar;
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


=== TEST 3: eval error - missing attribute access denies (permit skipped)
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/err_missing_attr.cedar;
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


=== TEST 4: eval error in forbid - forbid skipped, permit wins (allow)
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/err_forbid_skipped.cedar;
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
