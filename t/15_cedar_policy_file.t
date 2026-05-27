use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_shuffle();
no_root_location();

run_tests();

__DATA__

=== TEST 1: three policy files merge correctly within a single directive
            - GET permitted by file 1 and file 3, no forbid matches => 200
--- http_config
    auth_cedar_policy_file def
        $TEST_NGINX_CONF_DIR/policies/basic_permit.cedar
        $TEST_NGINX_CONF_DIR/policies/permit_post.cedar
        $TEST_NGINX_CONF_DIR/policies/basic_forbid.cedar;
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


=== TEST 1b: three policy files merge correctly within a single directive
             - DELETE matches the forbid policy from file 3 => 403 (forbid
             wins over permits)
--- http_config
    auth_cedar_policy_file def
        $TEST_NGINX_CONF_DIR/policies/basic_permit.cedar
        $TEST_NGINX_CONF_DIR/policies/permit_post.cedar
        $TEST_NGINX_CONF_DIR/policies/basic_forbid.cedar;
--- config
    location /test.html {
        auth_cedar on;
    }
--- request
DELETE /test.html
--- error_code: 403


=== TEST 2: empty policy file followed by a real one - merge does not
            dereference a NULL policies array (B1 regression)
--- http_config
    auth_cedar_policy_file def
        $TEST_NGINX_CONF_DIR/policies/empty.cedar
        $TEST_NGINX_CONF_DIR/policies/basic_permit.cedar;
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


=== TEST 3: real policy followed by an empty one - second file contributes
            nothing but does not corrupt the merged set
--- http_config
    auth_cedar_policy_file def
        $TEST_NGINX_CONF_DIR/policies/basic_permit.cedar
        $TEST_NGINX_CONF_DIR/policies/empty.cedar;
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


=== TEST 4: oversized policy file is rejected at config time (S2)
--- http_config eval
    use File::Temp qw(tempfile);
    my ($fh, $path) = tempfile(
        "auth_cedar_too_big_XXXXXX",
        SUFFIX => ".cedar",
        TMPDIR => 1,
        UNLINK => 1,
    );
    print $fh "a" x (17 * 1024 * 1024);
    close $fh;
    "auth_cedar_policy_file def $path;";
--- config
    location /test.html {
        auth_cedar on;
    }
--- must_die
--- error_log
exceeds


=== TEST 5: missing policy file fails configuration
--- http_config
    auth_cedar_policy_file def $TEST_NGINX_CONF_DIR/policies/does_not_exist.cedar;
--- config
    location /test.html {
        auth_cedar on;
    }
--- must_die
--- error_log eval
qr/(No such file|failed)/
