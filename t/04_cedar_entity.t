use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_shuffle();
no_root_location();

run_tests();

__DATA__

=== TEST 1: principal attr mapping - role admin allowed
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/when_unless.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_attr role "admin";
        auth_cedar_principal_attr tenant "acme";
        auth_cedar_resource_attr tenant "acme";
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 200
--- response_body
OK


=== TEST 2: principal attr mapping - role user denied (no matching permit)
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/when_unless.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_attr role "user";
        auth_cedar_principal_attr tenant "acme";
        auth_cedar_resource_attr tenant "acme";
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 403


=== TEST 3: tenant isolation - same tenant allowed (admin)
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/when_unless.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_attr role "admin";
        auth_cedar_principal_attr tenant "acme";
        auth_cedar_resource_attr tenant "acme";
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 200


=== TEST 4: tenant isolation - different tenant denied
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/when_unless.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_attr role "admin";
        auth_cedar_principal_attr tenant "acme";
        auth_cedar_resource_attr tenant "other";
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 403


=== TEST 5: custom resource type
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/basic_permit.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_resource_type "api_endpoint";
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 200


=== TEST 6: context.ip - loopback allowed
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/context_ip.cedar;
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


=== TEST 7: principal attr with nginx variable expansion
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/when_unless.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_attr role $http_x_role;
        auth_cedar_principal_attr tenant $http_x_tenant;
        auth_cedar_resource_attr tenant "acme";
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- more_headers
X-Role: admin
X-Tenant: acme
--- error_code: 200
--- response_body
OK


=== TEST 8: principal attr with nginx variable - denied role
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/when_unless.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_attr role $http_x_role;
        auth_cedar_principal_attr tenant $http_x_tenant;
        auth_cedar_resource_attr tenant "acme";
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- more_headers
X-Role: user
X-Tenant: acme
--- error_code: 403


=== TEST 9: principal attr with nginx variable - empty header skipped
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/when_unless.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_attr role $http_x_role;
        auth_cedar_principal_attr tenant "acme";
        auth_cedar_resource_attr tenant "acme";
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 403


=== TEST 10: custom deny status
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/default_deny.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_deny_status 401;
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 401


=== TEST 11: context.ip - user override with matching header allows
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/context_ip.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_context_attr ip $http_x_real_ip;
    }
--- user_files
>>> test.html
OK
--- more_headers
X-Real-IP: 127.0.0.1
--- request
GET /test.html
--- error_code: 200
--- response_body
OK


=== TEST 12: context.ip - user override with non-matching header denies
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/context_ip.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_context_attr ip $http_x_real_ip;
    }
--- user_files
>>> test.html
OK
--- more_headers
X-Real-IP: 10.0.0.1
--- request
GET /test.html
--- error_code: 403


=== TEST 13: duplicate principal_attr name rejected at config time
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/when_unless.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_attr role "admin";
        auth_cedar_principal_attr role "user";
    }
--- must_die
--- error_log
duplicate "auth_cedar_principal_attr" name "role"


=== TEST 14: duplicate resource_attr name rejected at config time
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/when_unless.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_resource_attr tenant "acme";
        auth_cedar_resource_attr tenant "other";
    }
--- must_die
--- error_log
duplicate "auth_cedar_resource_attr" name "tenant"


=== TEST 15: duplicate context_attr name rejected at config time
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/context_ip.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_context_attr ip "127.0.0.1";
        auth_cedar_context_attr ip "10.0.0.1";
    }
--- must_die
--- error_log
duplicate "auth_cedar_context_attr" name "ip"


=== TEST 16: same name across different attr scopes is allowed
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/when_unless.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_principal_attr tenant "acme";
        auth_cedar_resource_attr tenant "acme";
        auth_cedar_principal_attr role "admin";
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 200
