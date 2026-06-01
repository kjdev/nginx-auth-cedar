use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_shuffle();
no_root_location();

run_tests();

__DATA__

=== TEST 1: ip().isLoopback() - 127.0.0.1 is loopback (permit)
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/ext_ip_loopback.cedar;
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


=== TEST 2: ip().isLoopback() - 8.8.8.8 is not loopback (deny)
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/ext_ip_loopback_false.cedar;
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


=== TEST 3: ip().isIpv4() / isIpv6() distinguish address families
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/ext_ip_family.cedar;
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


=== TEST 4: ip().isMulticast() covers v4 (224/4) and v6 (ff00::/8)
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/ext_ip_multicast.cedar;
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


=== TEST 5: ip().isInRange() respects receiver / argument specificity
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/ext_ip_in_range.cedar;
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


=== TEST 6: decimal ordering - lessThan / lessThanOrEqual / greaterThan / greaterThanOrEqual
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/ext_decimal_ordering.cedar;
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


=== TEST 7: decimal - negative values preserve ordering
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/ext_decimal_negative.cedar;
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


=== TEST 8: datetime - construction, offset normalization, and ordering
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/ext_datetime_compare.cedar;
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


=== TEST 9: datetime methods - offset / durationSince / toDate / toTime
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/ext_datetime_methods.cedar;
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


=== TEST 10: datetime - invalid trailing 'T' errors and falls through to deny
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/ext_datetime_invalid.cedar;
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


=== TEST 11: duration - unit equivalence, multi-unit parsing, signed ordering
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/ext_duration_units.cedar;
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


=== TEST 12: duration - toSeconds / toMinutes / toHours / toDays conversions
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/ext_duration_conversions.cedar;
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


=== TEST 13: duration - out-of-order units error and fall through to deny
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/ext_duration_invalid.cedar;
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
