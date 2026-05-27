use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_shuffle();
no_root_location();

run_tests();

__DATA__

=== TEST 1: $cedar_policy_id - permit decision exposes @id of matched permit
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/anno_permit_id.cedar;
--- config
    location /test.html {
        auth_cedar on;
        add_header X-Cedar-Policy $cedar_policy_id always;
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 200
--- response_headers
X-Cedar-Policy: permit-all-get


=== TEST 2: $cedar_advice - empty when policy has no @advice annotation
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/anno_permit_id.cedar;
--- config
    location /test.html {
        auth_cedar on;
        add_header X-Cedar-Advice $cedar_advice always;
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 200
--- response_headers
!X-Cedar-Advice


=== TEST 3: $cedar_policy_id - forbid decision exposes @id of matched forbid
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/anno_forbid_advice.cedar;
--- config
    location /test.html {
        auth_cedar on;
        add_header X-Cedar-Policy $cedar_policy_id always;
    }
--- user_files
>>> test.html
OK
--- request
DELETE /test.html
--- error_code: 403
--- response_headers
X-Cedar-Policy: forbid-delete


=== TEST 4: $cedar_advice - forbid decision exposes @advice
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/anno_forbid_advice.cedar;
--- config
    location /test.html {
        auth_cedar on;
        add_header X-Cedar-Advice $cedar_advice always;
    }
--- user_files
>>> test.html
OK
--- request
DELETE /test.html
--- error_code: 403
--- response_headers
X-Cedar-Advice: DELETE is not allowed on this resource


=== TEST 5: $cedar_policy_id - permit decision under same forbid policy
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/anno_forbid_advice.cedar;
--- config
    location /test.html {
        auth_cedar on;
        add_header X-Cedar-Policy $cedar_policy_id always;
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 200
--- response_headers
!X-Cedar-Policy


=== TEST 6: $cedar_policy_id / $cedar_advice - default deny has no detail
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/empty.cedar;
--- config
    location /test.html {
        auth_cedar on;
        add_header X-Cedar-Policy $cedar_policy_id always;
        add_header X-Cedar-Advice $cedar_advice always;
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 403
--- response_headers
!X-Cedar-Policy
!X-Cedar-Advice


=== TEST 7: $cedar_policy_id - auth_cedar off skips evaluation
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/anno_permit_id.cedar;
--- config
    location /test.html {
        add_header X-Cedar-Policy $cedar_policy_id always;
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 200
--- response_headers
!X-Cedar-Policy


=== TEST 8: $cedar_policy_id - permit without annotation exposes empty
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/anno_no_annotation.cedar;
--- config
    location /test.html {
        auth_cedar on;
        add_header X-Cedar-Policy $cedar_policy_id always;
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 200
--- response_headers
!X-Cedar-Policy
