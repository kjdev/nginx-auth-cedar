use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_shuffle();
no_root_location();

run_tests();

__DATA__

=== TEST 1: like - prefix wildcard "admin*" matches "administrator"
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/str_like_prefix.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_attr role $http_x_role;
    }
--- user_files
>>> test.html
OK
--- more_headers
X-Role: administrator
--- request
GET /test.html
--- error_code: 200


=== TEST 2: like - prefix wildcard "admin*" does not match "user"
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/str_like_prefix.cedar;
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


=== TEST 3: like - embedded wildcard "a*c" matches "abc"
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/str_like_middle.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_attr role $http_x_role;
    }
--- user_files
>>> test.html
OK
--- more_headers
X-Role: abc
--- request
GET /test.html
--- error_code: 200


=== TEST 4: like - embedded wildcard "a*c" matches "axyzc"
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/str_like_middle.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_attr role $http_x_role;
    }
--- user_files
>>> test.html
OK
--- more_headers
X-Role: axyzc
--- request
GET /test.html
--- error_code: 200


=== TEST 5: like - escaped `\*` matches literal "*" only
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/str_like_escape.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_attr role $http_x_role;
    }
--- user_files
>>> test.html
OK
--- more_headers
X-Role: ad*min
--- request
GET /test.html
--- error_code: 200


=== TEST 6: like - escaped `\*` does not match "adXmin"
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/str_like_escape.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_attr role $http_x_role;
    }
--- user_files
>>> test.html
OK
--- more_headers
X-Role: adXmin
--- request
GET /test.html
--- error_code: 403


=== TEST 7: string escape `\t` matches header containing tab
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/str_escape_tab.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_attr role $http_x_role;
    }
--- user_files
>>> test.html
OK
--- more_headers eval
"X-Role: a\tb"
--- request
GET /test.html
--- error_code: 200


=== TEST 8: string escape `\xHH` - "\x41dmin" matches "Admin"
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/str_escape_hex.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_attr role $http_x_role;
    }
--- user_files
>>> test.html
OK
--- more_headers
X-Role: Admin
--- request
GET /test.html
--- error_code: 200


=== TEST 9: string escape `\u{4e2d}` - matches UTF-8 `中`
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/str_escape_unicode.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_attr role $http_x_role;
    }
--- user_files
>>> test.html
OK
--- more_headers eval
"X-Role: \xe4\xb8\xad"
--- request
GET /test.html
--- error_code: 200
