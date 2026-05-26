use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_shuffle();
no_root_location();

run_tests();

__DATA__

=== TEST 1: internal redirect via error_page re-evaluates the policy with
            the new location's attribute mappings — /allowed permits as
            admin, then content phase 404 redirects to /forbidden which
            re-runs the policy under role=guest and denies
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/redirect_admin.cedar;
--- config
    location /allowed {
        auth_cedar on;
        auth_cedar_principal_attr role "admin";
        error_page 404 = /forbidden;
    }
    location /forbidden {
        auth_cedar on;
        auth_cedar_principal_attr role "guest";
    }
--- request
GET /allowed
--- error_code: 403


=== TEST 2: internal redirect to a location with a relaxed mapping is
            re-evaluated — /strict denies under role=guest, error_page
            forwards to /lax.html which re-runs the policy under
            role=admin and allows
--- http_config
    auth_cedar_policy_file $TEST_NGINX_CONF_DIR/policies/redirect_admin.cedar;
--- config
    location /strict {
        auth_cedar on;
        auth_cedar_principal_attr role "guest";
        error_page 403 = /lax.html;
    }
    location /lax.html {
        auth_cedar on;
        auth_cedar_principal_attr role "admin";
    }
--- user_files
>>> lax.html
LAX
--- request
GET /strict
--- error_code: 200
--- response_body
LAX


=== TEST 3: re-entering the same location reuses the cached decision
            (sanity check that the cache is not invalidated unnecessarily)
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
