use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_shuffle();
no_root_location();

run_tests();

__DATA__

=== TEST 1: auth_cedar_principal_id - literal matches the policy
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/principal_id_match.cedar;
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
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/principal_id_match.cedar;
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
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/principal_id_match.cedar;
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
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/principal_id_match.cedar;
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
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/principal_id_match.cedar;
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
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/principal_id_match.cedar;
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
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/principal_id_match.cedar;
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


=== TEST 8: legacy $remote_user fallback via auth_basic - allowed user
            (no auth_cedar_principal_id; principal id comes from Basic
            auth's $remote_user, exercising the back-compat path)
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/principal_id_match.cedar;
--- config
    location /test.html {
        auth_basic           "test";
        auth_basic_user_file $TEST_NGINX_CONF_DIR/htpasswd;
        auth_cedar           on;
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- more_headers
Authorization: Basic YWxpY2U6c2VjcmV0
--- error_code: 200
--- response_body
OK


=== TEST 9: legacy $remote_user fallback via auth_basic - denied user
            (bob authenticates but principal_id_match only permits
            "alice", so Cedar must still deny)
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/principal_id_match.cedar;
--- config
    location /test.html {
        auth_basic           "test";
        auth_basic_user_file $TEST_NGINX_CONF_DIR/htpasswd;
        auth_cedar           on;
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- more_headers
Authorization: Basic Ym9iOnNlY3JldA==
--- error_code: 403


=== TEST 10: principal_id + principal_attr - both reach the policy
             (id and role match, expect 200)
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/principal_id_attr.cedar;
--- config
    location /test.html {
        auth_cedar                on;
        auth_cedar_principal_id   $http_x_principal;
        auth_cedar_principal_attr role $http_x_role;
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- more_headers
X-Principal: alice
X-Role: admin
--- error_code: 200
--- response_body
OK


=== TEST 11: principal_id + principal_attr - id matches but role does not
             (catches a regression where principal_attr would stop
             reaching the policy when principal_id is also set)
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/principal_id_attr.cedar;
--- config
    location /test.html {
        auth_cedar                on;
        auth_cedar_principal_id   $http_x_principal;
        auth_cedar_principal_attr role $http_x_role;
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- more_headers
X-Principal: alice
X-Role: viewer
--- error_code: 403


=== TEST 12: principal_id + principal_attr - role matches but id does not
             (catches a regression where principal_id would be ignored
             when principal_attr is also set)
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/principal_id_attr.cedar;
--- config
    location /test.html {
        auth_cedar                on;
        auth_cedar_principal_id   $http_x_principal;
        auth_cedar_principal_attr role $http_x_role;
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- more_headers
X-Principal: bob
X-Role: admin
--- error_code: 403


=== TEST 13: auth_cedar_principal_id empty does NOT fall back to
             $remote_user even when Basic Auth populated it
             (locks the "explicit directive is strict override" rule
             from issue #004 — alice is authenticated and would match
             the policy via the back-compat path, but the explicitly
             configured empty principal_id must take precedence and
             deny)
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/principal_id_match.cedar;
--- config
    location /test.html {
        auth_basic              "test";
        auth_basic_user_file    $TEST_NGINX_CONF_DIR/htpasswd;
        auth_cedar              on;
        auth_cedar_principal_id $http_x_principal;
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- more_headers
Authorization: Basic YWxpY2U6c2VjcmV0
--- error_code: 403
--- error_log
principal=""
