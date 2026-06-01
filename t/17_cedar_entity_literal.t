use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_shuffle();
no_root_location();

run_tests();

__DATA__

=== TEST 1: principal entity literal attribute resolves (match)
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/el_principal_attr.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_id "alice";
        auth_cedar_principal_attr role "admin";
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 200


=== TEST 2: principal entity literal attribute resolves (mismatch denies)
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/el_principal_attr.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_id "alice";
        auth_cedar_principal_attr role "user";
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 403


=== TEST 3: entity literal and request variable resolve to the same value
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/el_principal_eq_request.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_id "alice";
        auth_cedar_principal_attr role "admin";
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 200


=== TEST 4: `has` on a request entity literal - present attribute
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/el_principal_has.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_id "alice";
        auth_cedar_principal_attr role "admin";
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 200


=== TEST 5: `has` on a request entity literal - absent attribute denies
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/el_principal_has_missing.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_id "alice";
        auth_cedar_principal_attr role "admin";
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 403


=== TEST 6: resource entity literal attribute resolves (id is the request URI)
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/el_resource_attr.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_resource_attr tenant "acme";
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 200


=== TEST 7: non-request entity literal attribute cannot resolve (== denies)
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/el_non_request.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_id "alice";
        auth_cedar_principal_attr role "admin";
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 403


=== TEST 8: non-request entity literal attribute under `!=` still denies
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/el_non_request_neq.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_id "alice";
        auth_cedar_principal_attr role "admin";
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 403
