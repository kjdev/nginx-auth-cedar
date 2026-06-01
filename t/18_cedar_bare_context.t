use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_shuffle();
no_root_location();

run_tests();

__DATA__

=== TEST 1: bare context materializes as a record and equals itself
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/bc_self.cedar;
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


=== TEST 2: `has` on the bare context record - present field
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/bc_has_attr.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_context_attr foo "bar";
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 200


=== TEST 3: `has` on the bare context record - absent field denies
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/bc_has_missing.cedar;
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


=== TEST 4: bare context `!=` a non-matching record literal holds
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/bc_neq_literal.cedar;
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


=== TEST 5: bare context `==` a matching record literal (ip pinned)
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/bc_eq_literal.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_context_attr ip "127.0.0.1";
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 200


=== TEST 6: bare context `==` a larger record literal (size mismatch denies)
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/bc_eq_size_mismatch.cedar;
--- config
    location /test.html {
        auth_cedar on;
        auth_cedar_context_attr ip "127.0.0.1";
    }
--- user_files
>>> test.html
OK
--- request
GET /test.html
--- error_code: 403
