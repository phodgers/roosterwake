/*
 * Relay URL parsing and the plaintext policy.
 *
 * SPDX-License-Identifier: MIT
 */
#include <string.h>

#include "net/url.h"
#include "rw_test.h"

static void test_parsing(void) {
    rw_test_begin("relay url parsing");

    rw_url_t u;

    RW_CHECK(rw_url_parse("wss://relay.remotewake.com/ws", &u));
    RW_CHECK(u.tls);
    RW_CHECK_EQ_STR(u.host, "relay.remotewake.com");
    RW_CHECK_EQ_INT(u.port, 443);
    RW_CHECK_EQ_STR(u.path, "/ws");

    RW_CHECK(rw_url_parse("ws://192.168.1.10:8080/ws", &u));
    RW_CHECK(!u.tls);
    RW_CHECK_EQ_STR(u.host, "192.168.1.10");
    RW_CHECK_EQ_INT(u.port, 8080);
    RW_CHECK_EQ_STR(u.path, "/ws");

    /* No path means "/". */
    RW_CHECK(rw_url_parse("wss://relay.example.com", &u));
    RW_CHECK_EQ_STR(u.path, "/");
    RW_CHECK_EQ_INT(u.port, 443);

    RW_CHECK(rw_url_parse("wss://relay.example.com/", &u));
    RW_CHECK_EQ_STR(u.path, "/");

    /* Query strings are part of the request target. */
    RW_CHECK(rw_url_parse("wss://relay.example.com/ws?id=7", &u));
    RW_CHECK_EQ_STR(u.path, "/ws?id=7");
    RW_CHECK(rw_url_parse("wss://relay.example.com?id=7", &u));
    RW_CHECK_EQ_STR(u.path, "/?id=7");

    /* A fragment is never sent. */
    RW_CHECK(rw_url_parse("wss://relay.example.com/ws#frag", &u));
    RW_CHECK_EQ_STR(u.path, "/ws");

    /* Explicit default ports still parse. */
    RW_CHECK(rw_url_parse("wss://relay.example.com:443/ws", &u));
    RW_CHECK_EQ_INT(u.port, 443);

    /* Rejections. */
    RW_CHECK(!rw_url_parse("https://relay.example.com/ws", &u));
    RW_CHECK(!rw_url_parse("relay.example.com/ws", &u));
    RW_CHECK(!rw_url_parse("wss://", &u));
    RW_CHECK(!rw_url_parse("wss:///ws", &u));
    RW_CHECK(!rw_url_parse("wss://:443/ws", &u));
    RW_CHECK(!rw_url_parse("wss://host:0/ws", &u));
    RW_CHECK(!rw_url_parse("wss://host:99999/ws", &u));
    RW_CHECK(!rw_url_parse("wss://host:abc/ws", &u));
    RW_CHECK(!rw_url_parse(NULL, &u));

    /* userinfo is refused rather than discarded: credentials have no meaning in this protocol
     * and silently dropping something somebody typed is worse than saying the URL is wrong. */
    RW_CHECK(!rw_url_parse("wss://user:pass@relay.example.com/ws", &u));

    /* IPv6 literals: refused at parse time because lwIP is built without IPv6, so accepting
     * the syntax would only move the failure to connect time. */
    RW_CHECK(!rw_url_parse("wss://[2001:db8::1]/ws", &u));

    /* A host that does not fit the field. */
    char long_url[300];
    strcpy(long_url, "wss://");
    memset(long_url + 6, 'a', 200);
    strcpy(long_url + 206, ".example.com/ws");
    RW_CHECK(!rw_url_parse(long_url, &u));
}

static void test_plaintext_policy(void) {
    rw_test_begin("plaintext relay policy");

    /* PROTOCOL.md §1 and usbcfg.md §4: ws:// only to loopback and private space. */
    RW_CHECK(rw_url_plaintext_permitted("127.0.0.1"));
    RW_CHECK(rw_url_plaintext_permitted("127.1.2.3"));
    RW_CHECK(rw_url_plaintext_permitted("localhost"));
    RW_CHECK(rw_url_plaintext_permitted("10.0.0.1"));
    RW_CHECK(rw_url_plaintext_permitted("10.255.255.255"));
    RW_CHECK(rw_url_plaintext_permitted("192.168.1.10"));
    RW_CHECK(rw_url_plaintext_permitted("172.16.0.1"));
    RW_CHECK(rw_url_plaintext_permitted("172.31.255.254"));
    RW_CHECK(rw_url_plaintext_permitted("169.254.1.1"));

    /* 172.15 and 172.32 are outside the /12 — the boundary everyone gets wrong. */
    RW_CHECK(!rw_url_plaintext_permitted("172.15.0.1"));
    RW_CHECK(!rw_url_plaintext_permitted("172.32.0.1"));

    RW_CHECK(!rw_url_plaintext_permitted("8.8.8.8"));
    RW_CHECK(!rw_url_plaintext_permitted("1.1.1.1"));
    RW_CHECK(!rw_url_plaintext_permitted("relay.remotewake.com"));

    /*
     * A hostname is not evidence of where it points. The check runs before DNS on purpose: a
     * name that resolves to 192.168.1.10 today can resolve anywhere tomorrow, and the device
     * would have no way to notice.
     */
    RW_CHECK(!rw_url_plaintext_permitted("localhost.evil.example"));
    RW_CHECK(!rw_url_plaintext_permitted("192.168.1.10.evil.example"));

    /* Malformed dotted quads must not be mistaken for private addresses. */
    RW_CHECK(!rw_url_plaintext_permitted("192.168.1"));
    RW_CHECK(!rw_url_plaintext_permitted("192.168.1.1.1"));
    RW_CHECK(!rw_url_plaintext_permitted("192.168.1.256"));
    RW_CHECK(!rw_url_plaintext_permitted("192.168..1"));
    RW_CHECK(!rw_url_plaintext_permitted(""));
    RW_CHECK(!rw_url_plaintext_permitted(NULL));
}

void test_url(void) {
    test_parsing();
    test_plaintext_policy();
}
