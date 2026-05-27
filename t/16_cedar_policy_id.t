use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_shuffle();
no_root_location();

run_tests();

__DATA__

=== TEST 1: id-based selection - /get applies only the GET-permit policy
            (POST is denied as default deny, no permit_post in scope)
--- http_config
    auth_cedar_policy_file p_get  $TEST_NGINX_CONF_DIR/policies/basic_permit.cedar;
    auth_cedar_policy_file p_post $TEST_NGINX_CONF_DIR/policies/permit_post.cedar;
--- config
    location /test.html {
        auth_cedar p_get;
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 200
--- response_body
OK


=== TEST 1b: id-based selection - POST denied under /test.html with only
             p_get (no permit_post)
--- http_config
    auth_cedar_policy_file p_get  $TEST_NGINX_CONF_DIR/policies/basic_permit.cedar;
    auth_cedar_policy_file p_post $TEST_NGINX_CONF_DIR/policies/permit_post.cedar;
--- config
    location /test.html {
        auth_cedar p_get;
    }
--- user_files
>>> test.html
OK
--- request
POST /test.html
--- error_code: 403


=== TEST 2: multiple ids on one auth_cedar directive merge both policy sets
            - POST passes precontent (405 means the handler did not deny)
--- http_config
    auth_cedar_policy_file p_get  $TEST_NGINX_CONF_DIR/policies/basic_permit.cedar;
    auth_cedar_policy_file p_post $TEST_NGINX_CONF_DIR/policies/permit_post.cedar;
--- config
    location /test.html {
        auth_cedar p_get p_post;
    }
--- user_files
>>> test.html
OK
--- request
POST /test.html
--- error_code: 405


=== TEST 3: auth_cedar on applies the union of every declared id
            - POST passes precontent because p_post is in the union
--- http_config
    auth_cedar_policy_file p_get  $TEST_NGINX_CONF_DIR/policies/basic_permit.cedar;
    auth_cedar_policy_file p_post $TEST_NGINX_CONF_DIR/policies/permit_post.cedar;
--- config
    location /test.html {
        auth_cedar on;
    }
--- user_files
>>> test.html
OK
--- request
POST /test.html
--- error_code: 405


=== TEST 4: auth_cedar off skips the handler entirely - any method passes
--- http_config
    auth_cedar_policy_file p_get $TEST_NGINX_CONF_DIR/policies/basic_permit.cedar;
--- config
    location /test.html {
        auth_cedar off;
    }
--- user_files
>>> test.html
OK
--- request
DELETE /test.html
--- error_code: 405


=== TEST 5: referencing an undefined policy id fails configuration
--- http_config
    auth_cedar_policy_file p_get $TEST_NGINX_CONF_DIR/policies/basic_permit.cedar;
--- config
    location /test.html {
        auth_cedar ghost;
    }
--- must_die
--- error_log
references undefined policy id "ghost"


=== TEST 6: the reserved keyword "on" cannot be used as a policy id
--- http_config
    auth_cedar_policy_file on $TEST_NGINX_CONF_DIR/policies/basic_permit.cedar;
--- config
    location /test.html {
        auth_cedar on;
    }
--- must_die
--- error_log
invalid policy id "on"


=== TEST 7: the reserved keyword "off" cannot be used as a policy id
--- http_config
    auth_cedar_policy_file off $TEST_NGINX_CONF_DIR/policies/basic_permit.cedar;
--- config
    location /test.html {
        auth_cedar on;
    }
--- must_die
--- error_log
invalid policy id "off"


=== TEST 8: a policy id with disallowed characters is rejected
--- http_config
    auth_cedar_policy_file my.id $TEST_NGINX_CONF_DIR/policies/basic_permit.cedar;
--- config
    location /test.html {
        auth_cedar on;
    }
--- must_die
--- error_log
invalid policy id "my.id"


=== TEST 9: declaring the same id twice fails configuration
--- http_config
    auth_cedar_policy_file dup $TEST_NGINX_CONF_DIR/policies/basic_permit.cedar;
    auth_cedar_policy_file dup $TEST_NGINX_CONF_DIR/policies/basic_forbid.cedar;
--- config
    location /test.html {
        auth_cedar on;
    }
--- must_die
--- error_log
duplicate policy id "dup"


=== TEST 10: repeating the same id within a single auth_cedar directive
             is rejected
--- http_config
    auth_cedar_policy_file p_get $TEST_NGINX_CONF_DIR/policies/basic_permit.cedar;
--- config
    location /test.html {
        auth_cedar p_get p_get;
    }
--- must_die
--- error_log
duplicate policy id "p_get"


=== TEST 11: mixing "on"/"off" with policy ids in auth_cedar is rejected
--- http_config
    auth_cedar_policy_file p_get $TEST_NGINX_CONF_DIR/policies/basic_permit.cedar;
--- config
    location /test.html {
        auth_cedar on p_get;
    }
--- must_die
--- error_log
"on"/"off" cannot be mixed with policy ids


=== TEST 12: SELECTIVE mode survives internal redirect via error_page -
             /strict denies under role=guest, redirects to /lax.html which
             re-runs the policy with role=admin and allows
--- http_config
    auth_cedar_policy_file admin $TEST_NGINX_CONF_DIR/policies/redirect_admin.cedar;
--- config
    location /strict {
        auth_cedar admin;
        auth_cedar_principal_attr role "guest";
        error_page 403 = /lax.html;
    }
    location /lax.html {
        auth_cedar admin;
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


=== TEST 13: nested location inherits the parent's auth_cedar setting
             - POST denied at the inner location because the parent's
             p_get (GET-only permit) is inherited, proving the merge
--- http_config
    auth_cedar_policy_file p_get $TEST_NGINX_CONF_DIR/policies/basic_permit.cedar;
--- config
    location /outer {
        auth_cedar p_get;
        location /outer/inner {
        }
    }
--- request
POST /outer/inner
--- error_code: 403


=== TEST 14: auth_cedar on with no auth_cedar_policy_file directives fails
             configuration
--- http_config
--- config
    location /test.html {
        auth_cedar on;
    }
--- must_die
--- error_log
requires at least one


=== TEST 15: auth_cedar declared twice in the same location is rejected
--- http_config
    auth_cedar_policy_file p_get $TEST_NGINX_CONF_DIR/policies/basic_permit.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar p_get;
    }
--- must_die
--- error_log
"auth_cedar" directive is duplicate
