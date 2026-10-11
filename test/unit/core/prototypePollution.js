"use strict";

import assert from "assert";
import http from "http";
import stream from "stream";
import EventEmitter from "events";
import utils from "../../../lib/utils.js";
import mergeConfig from "../../../lib/core/mergeConfig.js";
import AxiosHeaders from "../../../lib/core/AxiosHeaders.js";
import AxiosError from "../../../lib/core/AxiosError.js";
import buildURL from "../../../lib/helpers/buildURL.js";
import httpAdapter from "../../../lib/adapters/http.js";
import defaults from "../../../lib/defaults/index.js";
import validator from "../../../lib/helpers/validator.js";
import axios from "../../../index.js";

const nodeMajorVersion = parseInt(process.versions.node.split('.')[0], 10);

describe("Prototype Pollution Protection", function () {
  afterEach(function () {
    // Clean up any pollution that might have occurred
    delete Object.prototype.polluted;
    delete Object.prototype.transport;
    delete Object.prototype.transformRequest;
    delete Object.prototype.transformResponse;
    delete Object.prototype.formSerializer;
    delete Object.prototype.env;
    delete Object.prototype.parseReviver;
    delete Object.prototype.validateStatus;
    delete Object.prototype.auth;
    delete Object.prototype.baseURL;
    delete Object.prototype.socketPath;
    delete Object.prototype.beforeRedirect;
    delete Object.prototype.insecureHTTPParser;
    delete Object.prototype.adapter;
    delete Object.prototype.httpAgent;
    delete Object.prototype.httpsAgent;
    delete Object.prototype.proxy;
    delete Object.prototype.maxContentLength;
    delete Object.prototype.maxBodyLength;
    delete Object.prototype.maxRedirects;
    delete Object.prototype.maxRate;
    delete Object.prototype.timeout;
    delete Object.prototype.transitional;
    delete Object.prototype.timeoutErrorMessage;
    delete Object.prototype.cancelToken;
    delete Object.prototype.signal;
    delete Object.prototype.decompress;
    delete Object.prototype.params;
    delete Object.prototype.paramsSerializer;
    delete Object.prototype.method;
    delete Object.prototype.withCredentials;
    delete Object.prototype.responseType;
    delete Object.prototype.fetchOptions;
    delete Object.prototype.config;
    delete Object.prototype.username;
    delete Object.prototype.password;
    delete Object.prototype.hostname;
    delete Object.prototype.host;
    delete Object.prototype.port;
    delete Object.prototype.protocol;
    delete Object.prototype.get;
    delete Object.prototype.set;
    delete Object.prototype.headers;
    delete Object.prototype.customNested;
    delete Object.prototype.common;
    delete Object.prototype.options;
    delete Object.prototype.post;
  });

  describe("utils.merge", function () {
    it("should filter __proto__ key at top level", function () {
      const result = utils.merge(
        {},
        { __proto__: { polluted: "yes" }, safe: "value" },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.safe, "value");
      assert.strictEqual(result.hasOwnProperty("__proto__"), false);
    });

    it("should filter constructor key at top level", function () {
      const result = utils.merge(
        {},
        { constructor: { polluted: "yes" }, safe: "value" },
      );

      assert.strictEqual(result.safe, "value");
      assert.strictEqual(result.hasOwnProperty("constructor"), false);
    });

    it("should filter prototype key at top level", function () {
      const result = utils.merge(
        {},
        { prototype: { polluted: "yes" }, safe: "value" },
      );

      assert.strictEqual(result.safe, "value");
      assert.strictEqual(result.hasOwnProperty("prototype"), false);
    });

    it("should filter __proto__ key in nested objects", function () {
      const result = utils.merge(
        {},
        {
          headers: {
            __proto__: { polluted: "nested" },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("__proto__"), false);
    });

    it("should filter constructor key in nested objects", function () {
      const result = utils.merge(
        {},
        {
          headers: {
            constructor: { prototype: { polluted: "nested" } },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("constructor"), false);
    });

    it("should filter prototype key in nested objects", function () {
      const result = utils.merge(
        {},
        {
          headers: {
            prototype: { polluted: "nested" },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("prototype"), false);
    });

    it("should filter dangerous keys in deeply nested objects", function () {
      const result = utils.merge(
        {},
        {
          level1: {
            level2: {
              __proto__: { polluted: "deep" },
              prototype: { polluted: "deep" },
              safe: "value",
            },
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.level1.level2.safe, "value");
      assert.strictEqual(
        result.level1.level2.hasOwnProperty("__proto__"),
        false,
      );
    });

    it("should still merge regular properties correctly", function () {
      const result = utils.merge({ a: 1, b: { c: 2 } }, { b: { d: 3 }, e: 4 });

      assert.strictEqual(result.a, 1);
      assert.strictEqual(result.b.c, 2);
      assert.strictEqual(result.b.d, 3);
      assert.strictEqual(result.e, 4);
    });

    it("should handle JSON.parse payloads safely", function () {
      const malicious = JSON.parse('{"__proto__": {"polluted": "yes"}}');
      const result = utils.merge({}, malicious);

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.hasOwnProperty("__proto__"), false);
    });

    it("should handle nested JSON.parse payloads safely", function () {
      const malicious = JSON.parse(
        '{"headers": {"constructor": {"prototype": {"polluted": "yes"}}}}',
      );
      const result = utils.merge({}, malicious);

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers.hasOwnProperty("constructor"), false);
    });
  });

  describe("mergeConfig", function () {
    it("should filter dangerous keys at top level", function () {
      const result = mergeConfig(
        {},
        {
          __proto__: { polluted: "yes" },
          constructor: { polluted: "yes" },
          prototype: { polluted: "yes" },
          url: "/api/test",
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.url, "/api/test");
      assert.strictEqual(result.hasOwnProperty("__proto__"), false);
      assert.strictEqual(result.hasOwnProperty("constructor"), false);
      assert.strictEqual(result.hasOwnProperty("prototype"), false);
    });

    it("should filter dangerous keys in headers", function () {
      const result = mergeConfig(
        {},
        {
          headers: {
            __proto__: { polluted: "yes" },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("__proto__"), false);
    });

    it("should filter dangerous keys in custom config properties", function () {
      const result = mergeConfig(
        {},
        {
          customProp: {
            __proto__: { polluted: "yes" },
            safe: "value",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.customProp.safe, "value");
      assert.strictEqual(result.customProp.hasOwnProperty("__proto__"), false);
    });

    it("should not inherit transport from Object.prototype", function () {
      Object.prototype.transport = { request: function () {} };
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(result.hasOwnProperty("transport"), false);
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "transport"),
        false
      );
    });

    it("should not inherit transformRequest from Object.prototype", function () {
      Object.prototype.transformRequest = function () { return "hijacked"; };
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "transformRequest"),
        false
      );
    });

    it("should not inherit transformResponse from Object.prototype", function () {
      Object.prototype.transformResponse = function () { return "hijacked"; };
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "transformResponse"),
        false
      );
    });

    it("should not inherit arbitrary keys from Object.prototype", function () {
      Object.prototype.polluted = "yes";
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "polluted"),
        false
      );
    });

    it("should still merge configs correctly", function () {
      const config1 = {
        baseURL: "https://api.example.com",
        timeout: 1000,
        headers: {
          common: {
            Accept: "application/json",
          },
        },
      };

      const config2 = {
        url: "/users",
        timeout: 5000,
        headers: {
          common: {
            "Content-Type": "application/json",
          },
        },
      };

      const result = mergeConfig(config1, config2);

      assert.strictEqual(result.baseURL, "https://api.example.com");
      assert.strictEqual(result.url, "/users");
      assert.strictEqual(result.timeout, 5000);
      assert.strictEqual(result.headers.common.Accept, "application/json");
      assert.strictEqual(
        result.headers.common["Content-Type"],
        "application/json",
      );
    });
  });

  describe('GHSA-w9j2-pvgh-6h63 validateStatus merge', function () {
    it('should not inherit a polluted validateStatus during mergeConfig', function () {
      Object.prototype.validateStatus = () => true;
      const merged = mergeConfig(defaults, { url: '/x' });
      assert.strictEqual(merged.validateStatus, defaults.validateStatus);
    });

    it('should keep 4xx/5xx responses rejected when Object.prototype.validateStatus is polluted', async function () {
      this.timeout(10000);
      Object.prototype.validateStatus = () => true;
      const server = http.createServer((req, res) => {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end('{"error":"unauthorized"}');
      });
      await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
      const { port } = server.address();
      try {
        let threw = false;
        try { await axios.get(`http://127.0.0.1:${port}/`); } catch (err) { threw = true; assert.strictEqual(err.response.status, 401); }
        assert.strictEqual(threw, true);
      } finally {
        await new Promise((resolve) => server.close(resolve));
      }
    });
  });

  // GHSA-q8qp-cvcw-x6jj: five config properties were read via direct property
  // access in the http adapter and when building the request URL, bypassing
  // hasOwnProperty and allowing prototype pollution gadgets (auth, baseURL,
  // socketPath, beforeRedirect, insecureHTTPParser).
  describe('GHSA-q8qp-cvcw-x6jj http adapter gadgets', function () {
    function startServer(handler) {
      return new Promise((resolve) => {
        const server = http.createServer(handler || ((req, res) => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ headers: req.headers, url: req.url }));
        }));
        server.listen(0, '127.0.0.1', () => resolve(server));
      });
    }

    function stopServer(server) {
      return new Promise((resolve) => server.close(resolve));
    }

    it('should not pick up Object.prototype.auth as an Authorization header', async function () {
      this.timeout(10000);
      Object.prototype.auth = { username: 'attacker', password: 'exfil' };

      const server = await startServer();
      const { port } = server.address();

      try {
        const res = await axios.get(`http://127.0.0.1:${port}/api`);
        assert.strictEqual(res.data.headers.authorization, undefined);
      } finally {
        await stopServer(server);
      }
    });

    it('should not pick up Object.prototype.socketPath and redirect the request', async function () {
      this.timeout(10000);
      Object.prototype.socketPath = '/tmp/axios-should-never-be-used.sock';

      const server = await startServer();
      const { port } = server.address();

      try {
        const res = await axios.get(`http://127.0.0.1:${port}/api`);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.data.url, '/api');
      } finally {
        await stopServer(server);
      }
    });

    it('should not expose Object.prototype.socketPath on the options passed to http.request', async function () {
      this.timeout(10000);
      Object.prototype.socketPath = '/tmp/axios-should-never-be-used.sock';

      let capturedSocketPath = 'not-called';
      const origRequest = http.request;
      http.request = function (options) {
        capturedSocketPath = options.socketPath;
        return origRequest.apply(this, arguments);
      };

      const server = await startServer();
      const { port } = server.address();
      try {
        await axios.get(`http://127.0.0.1:${port}/api`, { maxRedirects: 0 });
      } catch (_) {}
      finally {
        http.request = origRequest;
        await stopServer(server);
      }

      assert.strictEqual(capturedSocketPath, undefined);
    });

    it('should not invoke Object.prototype.beforeRedirect during redirects', async function () {
      this.timeout(10000);
      let hijackCalled = false;
      Object.prototype.beforeRedirect = function polluted() {
        hijackCalled = true;
      };

      const target = await startServer();
      const { port: targetPort } = target.address();

      const redirector = await startServer((req, res) => {
        res.writeHead(302, { Location: `http://127.0.0.1:${targetPort}/final` });
        res.end();
      });
      const { port: redirectorPort } = redirector.address();

      try {
        const res = await axios.get(`http://127.0.0.1:${redirectorPort}/start`);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(hijackCalled, false);
      } finally {
        await stopServer(redirector);
        await stopServer(target);
      }
    });

    it('should not invoke a polluted Object.prototype.config through the beforeRedirects hooks', async function () {
      this.timeout(10000);
      let hijackCalled = false;

      const target = await startServer();
      const { port: targetPort } = target.address();

      const redirector = await startServer((req, res) => {
        res.writeHead(302, { Location: `http://127.0.0.1:${targetPort}/final` });
        res.end();
      });
      const { port: redirectorPort } = redirector.address();

      Object.prototype.config = function polluted() {
        hijackCalled = true;
      };

      try {
        const res = await axios.get(`http://127.0.0.1:${redirectorPort}/start`);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.data.url, '/final');
        assert.strictEqual(hijackCalled, false);
      } finally {
        delete Object.prototype.config;
        await stopServer(redirector);
        await stopServer(target);
      }
    });

    it('should not enable insecureHTTPParser via Object.prototype', async function () {
      if (nodeMajorVersion < 14) this.skip();
      this.timeout(10000);
      // A raw TCP server emits a response that uses LF-only line terminators
      // instead of CRLF. Node's strict HTTP parser rejects this payload with
      // HPE_CR_EXPECTED; the insecure parser accepts it. Verified: with an
      // explicit `insecureHTTPParser: true` on the request config, this
      // payload is parsed successfully — so if Object.prototype.insecureHTTPParser
      // were picked up, the request would succeed. The request must fail when
      // the gadget is properly blocked.
      Object.prototype.insecureHTTPParser = true;

      const net = await import('net');
      const malformedPayload =
        'HTTP/1.1 200 OK\n' +
        'Content-Type: application/json\n' +
        'Content-Length: 2\n' +
        '\n' +
        '{}';
      const malformed = await new Promise((resolve) => {
        const srv = net.createServer((socket) => {
          socket.once('data', () => socket.end(malformedPayload));
        });
        srv.listen(0, '127.0.0.1', () => resolve(srv));
      });
      const { port } = malformed.address();

      try {
        let threw = false;
        let caughtCode = '';
        try {
          await axios.get(`http://127.0.0.1:${port}/`, {
            transitional: { clarifyTimeoutError: false },
          });
        } catch (err) {
          threw = true;
          caughtCode = String(err && (err.code || err.message));
        }
        assert.strictEqual(
          threw,
          true,
          `request should be rejected by the strict HTTP parser (got: ${caughtCode || 'success'})`
        );
        // The exact llhttp code for LF-only line terminators varies across
        // Node versions (historically HPE_LF_EXPECTED, more recently
        // HPE_CR_EXPECTED). Match any parser error to remain stable across
        // Node releases while still confirming the strict parser rejected
        // the payload.
        assert.match(
          caughtCode,
          /^HPE_/,
          `expected an HPE_* parser error, got: ${caughtCode}`
        );
      } finally {
        await new Promise((resolve) => malformed.close(resolve));
      }
    });

    it('should not pass insecureHTTPParser: true to http.request via Object.prototype', async function () {
      this.timeout(10000);
      Object.prototype.insecureHTTPParser = true;

      let capturedValue;
      const origRequest = http.request;
      http.request = function(options, callback) {
        capturedValue = options.insecureHTTPParser;
        return origRequest.apply(this, arguments);
      };

      const server = await startServer();
      const { port } = server.address();
      try {
        await axios.get(`http://127.0.0.1:${port}/`, { maxRedirects: 0 });
      } catch (_) {}
      finally {
        http.request = origRequest;
        await stopServer(server);
      }

      assert.strictEqual(capturedValue, false);
    });

    it('should not inject Proxy-Authorization from polluted Object.prototype.auth', async function () {
      this.timeout(10000);
      // setProxy reads `proxy.auth` directly. When `proxy` is a
      // URL instance from the environment proxy or a plain object without an own `auth`,
      // a polluted Object.prototype.auth would otherwise be base64-encoded into the
      // Proxy-Authorization header, leaking attacker-controlled credentials.
      Object.prototype.auth = { username: 'attacker', password: 'exfil' };

      const proxy = await startServer();
      const { port: proxyPort } = proxy.address();

      const target = await startServer();
      const { port: targetPort } = target.address();

      try {
        const res = await axios.get(`http://127.0.0.1:${targetPort}/api`, {
          proxy: { host: '127.0.0.1', port: proxyPort, protocol: 'http' },
        });
        assert.strictEqual(res.status, 200);
        assert.strictEqual(
          res.data.headers['proxy-authorization'],
          undefined,
          'polluted Object.prototype.auth must not produce a Proxy-Authorization header'
        );
      } finally {
        await stopServer(target);
        await stopServer(proxy);
      }
    });

    it('should not inject Proxy-Authorization from polluted Object.prototype.username', async function () {
      this.timeout(10000);
      // The setProxy username/password branch builds basic creds from `proxy.username`
      // and `proxy.password`. For a plain object proxy, both reads must be guarded
      // against prototype pollution.
      Object.prototype.username = 'attacker';
      Object.prototype.password = 'exfil';

      const proxy = await startServer();
      const { port: proxyPort } = proxy.address();

      const target = await startServer();
      const { port: targetPort } = target.address();

      try {
        const res = await axios.get(`http://127.0.0.1:${targetPort}/api`, {
          proxy: { host: '127.0.0.1', port: proxyPort, protocol: 'http' },
        });
        assert.strictEqual(res.status, 200);
        assert.strictEqual(
          res.data.headers['proxy-authorization'],
          undefined,
          'polluted Object.prototype.username must not produce a Proxy-Authorization header'
        );
      } finally {
        await stopServer(target);
        await stopServer(proxy);
      }
    });
  });

  describe('GHSA-q8qp-cvcw-x6jj baseURL gadget', function () {
    // The baseURL branch in buildFullPath only runs when the requested URL is
    // relative (or allowAbsoluteUrls === false). An absolute URL would skip
    // baseURL regardless of pollution and would not exercise the gadget. We
    // therefore issue a relative GET and assert that either:
    //   - the request fails (no host to resolve) because baseURL is correctly
    //     absent from the merged config, OR
    //   - the request is fulfilled without hitting the hijacker.
    // Critically, hijackHit must always be false.
    it('should not hijack relative-URL requests via Object.prototype.baseURL', async function () {
      this.timeout(10000);
      let hijackHit = false;
      const hijacker = http.createServer((req, res) => {
        hijackHit = true;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"hijacked":true}');
      });
      await new Promise((resolve) => hijacker.listen(0, '127.0.0.1', resolve));
      const { port: hijackerPort } = hijacker.address();

      Object.prototype.baseURL = `http://127.0.0.1:${hijackerPort}`;

      try {
        let threw = false;
        try {
          await axios.get('/api');
        } catch (_err) {
          threw = true;
        }
        // Either the request fails (desired — no baseURL means no host) or it
        // resolves, but it must NOT hit the polluted hijacker.
        assert.strictEqual(hijackHit, false);
        assert.strictEqual(threw, true);
      } finally {
        await new Promise((resolve) => hijacker.close(resolve));
      }
    });

    // Second variant using allowAbsoluteUrls: false to force the baseURL path
    // even for a fully-qualified requested URL.
    it('should not hijack requests via Object.prototype.baseURL with allowAbsoluteUrls:false', async function () {
      this.timeout(10000);
      let hijackHit = false;
      const hijacker = http.createServer((req, res) => {
        hijackHit = true;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"hijacked":true}');
      });
      await new Promise((resolve) => hijacker.listen(0, '127.0.0.1', resolve));
      const { port: hijackerPort } = hijacker.address();

      const target = http.createServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"ok":true}');
      });
      await new Promise((resolve) => target.listen(0, '127.0.0.1', resolve));
      const { port: targetPort } = target.address();

      Object.prototype.baseURL = `http://127.0.0.1:${hijackerPort}`;

      try {
        // If the gadget were picked up, combineURLs(hijacker, `http://target`)
        // would route to the hijacker. It must not.
        let threw = false;
        try {
          await axios.get(`http://127.0.0.1:${targetPort}/api`, {
            allowAbsoluteUrls: false,
          });
        } catch (_err) {
          threw = true;
        }
        assert.strictEqual(hijackHit, false);
        // allowAbsoluteUrls:false + no baseURL → combineURLs not invoked
        // (baseURL falsy) → returns requested URL as-is → target receives it.
        // If baseURL were inherited from prototype, it would be truthy and
        // combineURLs would be invoked, routing to the hijacker.
        assert.strictEqual(threw, false);
      } finally {
        await new Promise((resolve) => hijacker.close(resolve));
        await new Promise((resolve) => target.close(resolve));
      }
    });

    it('should not see Object.prototype.baseURL on the merged request config', function () {
      Object.prototype.baseURL = 'https://evil.com';
      const merged = mergeConfig(defaults, { url: '/api/users' });
      assert.strictEqual(merged.baseURL, undefined);
      assert.strictEqual(axios.getUri({ url: '/api/users' }), '/api/users');
    });
  });

  // Structural defense: mergeConfig returns a null-prototype object, so any
  // property read that is not an own property of config cannot inherit from
  // Object.prototype. Adding a new key to Object.prototype must never appear
  // as a property of the merged config.
  describe('mergeConfig null-prototype structural defense', function () {
    it('should return an object whose prototype is null', function () {
      const merged = mergeConfig({ url: '/x' }, { method: 'get' });
      assert.strictEqual(Object.getPrototypeOf(merged), null);
    });

    it('should preserve hasOwnProperty as a callable own slot', function () {
      const merged = mergeConfig({}, { url: '/x', method: 'get' });
      assert.strictEqual(typeof merged.hasOwnProperty, 'function');
      assert.strictEqual(merged.hasOwnProperty('url'), true);
      assert.strictEqual(merged.hasOwnProperty('method'), true);
      assert.strictEqual(merged.hasOwnProperty('bogus'), false);
    });

    it('should not serialize hasOwnProperty slot via Object.keys', function () {
      const merged = mergeConfig({ url: '/x' }, {});
      assert.ok(!Object.keys(merged).includes('hasOwnProperty'));
    });

    it('should not expose arbitrary polluted keys as inherited properties', function () {
      Object.prototype.polluted = 'attacker';
      try {
        const merged = mergeConfig({ url: '/x' }, {});
        assert.strictEqual(merged.polluted, undefined);
      } finally {
        delete Object.prototype.polluted;
      }
    });
  });

  describe('GHSA-q8qp-cvcw-x6jj validator.assertOptions', function () {
    it('should not use a polluted non-function Object.prototype entry as a validator', function () {
      Object.prototype.customOption = 'not-a-function';
      try {
        assert.doesNotThrow(function () {
          validator.assertOptions({ customOption: 1 }, {}, true);
        });
      } finally {
        delete Object.prototype.customOption;
      }
    });

    it('should not let a polluted Object.prototype validator accept an unknown option', function () {
      Object.prototype.bogusOption = function () {
        return true;
      };
      try {
        assert.throws(function () {
          validator.assertOptions({ bogusOption: 1 }, {}, false);
        }, /Unknown option bogusOption/);
      } finally {
        delete Object.prototype.bogusOption;
      }
    });
  });

  // Verify every gadget enumerated in the audit (extension of GHSA-q8qp-cvcw-x6jj)
  // is neutralized end-to-end by the null-prototype config.
  describe('Full gadget coverage via null-prototype config', function () {
    function startEcho(handler) {
      return new Promise((resolve) => {
        const server = http.createServer(handler || ((req, res) => {
          let body = '';
          req.on('data', (c) => (body += c));
          req.on('end', () => {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              url: req.url,
              method: req.method,
              headers: req.headers,
              body,
            }));
          });
        }));
        server.listen(0, '127.0.0.1', () => resolve(server));
      });
    }
    const stop = (s) => new Promise((r) => s.close(r));

    it('should ignore polluted transformRequest', async function () {
      this.timeout(10000);
      let invoked = false;
      Object.prototype.transformRequest = function polluted() {
        invoked = true;
        return 'INJECTED';
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.post(`http://127.0.0.1:${port}/`, { hello: 'world' });
        assert.strictEqual(invoked, false);
        assert.notStrictEqual(res.data.body, 'INJECTED');
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted transformResponse', async function () {
      this.timeout(10000);
      let invoked = false;
      Object.prototype.transformResponse = function polluted() {
        invoked = true;
        return 'HIJACKED';
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(invoked, false);
        assert.notStrictEqual(res.data, 'HIJACKED');
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted adapter', async function () {
      this.timeout(10000);
      let hijacked = false;
      Object.prototype.adapter = function pollutedAdapter() {
        hijacked = true;
        return Promise.resolve({ data: 'pwned', status: 200, statusText: 'OK', headers: {}, config: {}, request: {} });
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/ok`);
        assert.strictEqual(hijacked, false);
        assert.notStrictEqual(res.data, 'pwned');
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted httpAgent', async function () {
      this.timeout(10000);
      let agentUsed = false;
      Object.prototype.httpAgent = new http.Agent({
        keepAlive: false,
      });
      // Wrap createConnection to detect usage
      const origCreate = Object.prototype.httpAgent.createConnection;
      Object.prototype.httpAgent.createConnection = function (...args) {
        agentUsed = true;
        return origCreate.apply(this, args);
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(agentUsed, false);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted proxy', async function () {
      this.timeout(10000);
      Object.prototype.proxy = {
        protocol: 'http',
        host: '127.0.0.1',
        port: 1, // would fail if actually used
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted maxContentLength', async function () {
      this.timeout(10000);
      // Polluted tiny limit would reject a normal response if applied.
      Object.prototype.maxContentLength = 1;

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted maxRedirects', async function () {
      this.timeout(10000);
      // Pollute with 0 — if picked up, follow-redirects path would be skipped.
      // We make sure regular requests still succeed via the expected path.
      Object.prototype.maxRedirects = 0;

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted timeout at the merged config level', function () {
      Object.prototype.timeout = 1;
      const merged = mergeConfig({}, { url: '/x' });
      assert.strictEqual(Object.prototype.hasOwnProperty.call(merged, 'timeout'), false);
      assert.strictEqual(merged.timeout, undefined);
    });

    it('should ignore polluted timeoutErrorMessage', async function () {
      this.timeout(10000);
      Object.prototype.timeoutErrorMessage = 'INJECTED_TIMEOUT';
      // Not easy to assert without triggering a real timeout; just confirm
      // normal requests still succeed and do not read the polluted key.
      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted transitional', async function () {
      this.timeout(10000);
      Object.prototype.transitional = { forcedJSONParsing: true, silentJSONParsing: false };
      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted params and paramsSerializer', async function () {
      this.timeout(10000);
      let serializerInvoked = false;
      Object.prototype.params = { injected: 'yes' };
      Object.prototype.paramsSerializer = function polluted() {
        serializerInvoked = true;
        return 'injected=yes';
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/x`);
        assert.strictEqual(serializerInvoked, false);
        assert.strictEqual(res.data.url, '/x');
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted method', async function () {
      this.timeout(10000);
      Object.prototype.method = 'DELETE';
      const server = await startEcho();
      const { port } = server.address();
      try {
        // axios.get should still send GET, not DELETE.
        const res = await axios.get(`http://127.0.0.1:${port}/ok`);
        assert.strictEqual(res.data.method, 'GET');
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted decompress', async function () {
      this.timeout(10000);
      Object.prototype.decompress = false;
      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted responseType', async function () {
      this.timeout(10000);
      Object.prototype.responseType = 'arraybuffer';
      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        // When responseType is not set on config, json parsing should apply
        // and res.data should be an object, not an ArrayBuffer/Buffer.
        assert.strictEqual(typeof res.data, 'object');
        assert.ok(!Buffer.isBuffer(res.data));
      } finally {
        await stop(server);
      }
    });
  });

  // utils.merge previously read `result[targetKey]` directly, which walks the
  // prototype chain. A polluted Object.prototype.<key> object would surface as
  // the existing value and be merged into the result.
  describe('utils.merge prototype-chain read', function () {
    it('should not pick up polluted Object.prototype.<key> as the existing value', function () {
      Object.prototype.headers = { evil: 'yes' };

      const result = utils.merge({}, { headers: { 'Content-Type': 'application/json' } });

      assert.strictEqual(result.headers.evil, undefined);
      assert.strictEqual(result.headers['Content-Type'], 'application/json');
    });

    it('should not absorb polluted nested objects when the key is absent from inputs', function () {
      // When the source does not carry `customNested`, the merged result should
      // not surface it either, even if Object.prototype carries it.
      Object.prototype.customNested = { evil: 'yes' };

      const result = utils.merge({}, { safe: 'value' });

      assert.strictEqual(result.hasOwnProperty('customNested'), false);
      assert.strictEqual(result.safe, 'value');
    });

    it('should not copy a polluted Object.prototype.common into the merged default headers', function () {
      Object.prototype.common = { 'X-Poisoned': 'yes' };

      const result = mergeConfig(defaults, { url: '/x' });

      assert.strictEqual(utils.hasOwnProp(result.headers.common, 'X-Poisoned'), false);
      assert.strictEqual(result.headers.common.Accept, defaults.headers.common.Accept);
    });
  });

  // Object.defineProperty calls a HasProperty check on `get`/`set` of the
  // descriptor. A polluted Object.prototype.get with a non-function value would
  // throw TypeError at every defineProperty site that uses a plain literal
  // descriptor. Each fixed site should be shielded with `__proto__: null`.
  describe('Object.defineProperty descriptor literals', function () {
    it('should construct AxiosError when Object.prototype.get is polluted', function () {
      Object.prototype.get = 'attacker';

      const err = new AxiosError('hello', 'ECODE');

      assert.strictEqual(err.message, 'hello');
      assert.strictEqual(err.code, 'ECODE');
    });

    it('should construct AxiosHeaders accessor methods when Object.prototype.get is polluted', function () {
      Object.prototype.get = 'attacker';

      // AxiosHeaders.accessor uses Object.defineProperty on the prototype.
      // Triggering a fresh accessor definition exercises the descriptor literal.
      AxiosHeaders.accessor('X-Pp-Test');

      const h = new AxiosHeaders();
      h.setXPpTest('value');
      assert.strictEqual(h.getXPpTest(), 'value');
    });

    it('should not throw in mergeConfig when Object.prototype.get is polluted', function () {
      Object.prototype.get = 'attacker';

      const result = mergeConfig({}, { url: '/x', method: 'get' });

      assert.strictEqual(result.url, '/x');
      assert.strictEqual(result.method, 'get');
      assert.strictEqual(typeof result.hasOwnProperty, 'function');
    });

    it('should not throw in utils.extend when Object.prototype.get is polluted', function () {
      Object.prototype.get = 'attacker';

      const a = {};
      const b = { x: 1, fn() {} };
      utils.extend(a, b);

      assert.strictEqual(a.x, 1);
      assert.strictEqual(typeof a.fn, 'function');
    });

    it('should not throw in utils.extend with thisArg when Object.prototype.get is polluted', function () {
      Object.prototype.get = 'attacker';

      const a = {};
      const ctx = { tag: 'ctx' };
      const b = {
        method() {
          return this.tag;
        },
      };
      utils.extend(a, b, ctx);

      assert.strictEqual(a.method(), 'ctx');
    });

    it('should not throw in utils.inherits when Object.prototype.get is polluted', function () {
      Object.prototype.get = 'attacker';

      function Parent() {}
      function Child() {}
      utils.inherits(Child, Parent);

      assert.strictEqual(Child.prototype.constructor, Child);
      assert.strictEqual(Child.super, Parent.prototype);
    });

    it('should also be shielded against a polluted Object.prototype.set', function () {
      Object.prototype.set = 'attacker';

      // Same surface as `get` — ToPropertyDescriptor checks both. One spot-check
      // covers them all since they share the same fix.
      const err = new AxiosError('hello');
      assert.strictEqual(err.message, 'hello');

      const result = mergeConfig({}, { url: '/x' });
      assert.strictEqual(result.url, '/x');
    });

    it('should not break every request when Object.prototype.get/set are polluted', async function () {
      // Advisory DoS PoC: one polluted `get` key made mergeConfig throw on every
      // request. A stub adapter keeps the check independent of Node internals.
      Object.prototype.get = 'attacker';
      Object.prototype.set = 'attacker';

      let adapterCalled = false;
      const res = await axios.get('http://example.com/ok', {
        adapter: function stubAdapter(config) {
          adapterCalled = true;
          return Promise.resolve({
            data: { ok: true },
            status: 200,
            statusText: 'OK',
            headers: {},
            config,
            request: {},
          });
        },
      });

      assert.strictEqual(adapterCalled, true);
      assert.strictEqual(res.status, 200);
      assert.deepStrictEqual(res.data, { ok: true });
    });
  });

  // End-to-end regressions covering published advisory PoCs against full axios
  // request flow. Each test mirrors the exploit scenario from the advisory and
  // asserts the attack does not succeed.
  describe('advisory regression — full request flow', function () {
    function startServer(handler) {
      return new Promise((resolve) => {
        const server = http.createServer(handler || ((req, res) => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ method: req.method, headers: req.headers, url: req.url }));
        }));
        server.listen(0, '127.0.0.1', () => resolve(server));
      });
    }
    const stop = (s) => new Promise((r) => s.close(r));

    // Full MITM via prototype pollution gadget in
    // `config.proxy`. mergeConfig must not surface a polluted Object.prototype.proxy
    // as the merged config's proxy, otherwise every request would route through
    // an attacker-controlled host.
    it('polluted Object.prototype.proxy must not redirect requests through an attacker proxy', async function () {
      this.timeout(10000);
      const proxyHits = [];
      const attackerProxy = await startServer((req, res) => {
        proxyHits.push({
          url: req.url,
          authorization: req.headers.authorization,
          host: req.headers.host,
        });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"hijacked":true}');
      });

      const realHits = [];
      const realServer = await startServer((req, res) => {
        realHits.push({ url: req.url });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"data":"real"}');
      });

      try {
        Object.prototype.proxy = {
          protocol: 'http',
          host: '127.0.0.1',
          port: attackerProxy.address().port,
        };

        const realPort = realServer.address().port;
        const res = await axios.get(`http://127.0.0.1:${realPort}/api/secrets`, {
          auth: { username: 'admin', password: 'SuperSecret123!' },
        });

        assert.strictEqual(proxyHits.length, 0, 'attacker proxy must not receive any request');
        assert.strictEqual(realHits.length, 1, 'request must reach the real target');
        assert.deepStrictEqual(res.data, { data: 'real' });
      } finally {
        await stop(attackerProxy);
        await stop(realServer);
      }
    });

    // Credential theft and response hijacking via
    // prototype pollution gadget in config merge. A polluted
    // Object.prototype.transformResponse function would otherwise execute with
    // `this = config`, exposing `auth.username`/`auth.password` to the attacker.
    it('polluted Object.prototype.transformResponse must not be invoked or leak request credentials', async function () {
      this.timeout(10000);
      let invoked = false;
      let stolen = null;
      Object.prototype.transformResponse = function pollutedTransform(data) {
        invoked = true;
        stolen = {
          url: this && this.url,
          username: this && this.auth && this.auth.username,
          password: this && this.auth && this.auth.password,
          data,
        };
        return true;
      };

      const server = await startServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"secret":"keep-me"}');
      });

      try {
        const { port } = server.address();
        const res = await axios.get(`http://127.0.0.1:${port}/users`, {
          auth: { username: 'svc-account', password: 'prod-secret-key-123!' },
        });

        assert.strictEqual(invoked, false, 'polluted transformResponse must not run');
        assert.strictEqual(stolen, null, 'no request context must be captured');
        assert.deepStrictEqual(
          res.data,
          { secret: 'keep-me' },
          'response data must reach the caller untampered'
        );
      } finally {
        await stop(server);
      }
    });

    // Header injection: a polluted Object.prototype.common object was picked up
    // by utils.merge as the "existing" headers.common bucket while merging the
    // defaults, so every request carried the attacker's headers.
    it('polluted Object.prototype.common must not inject request headers', async function () {
      this.timeout(10000);
      Object.prototype.common = { 'X-Poisoned': 'yes', Authorization: 'Bearer attacker' };

      const server = await startServer();
      try {
        const { port } = server.address();
        const res = await axios.get(`http://127.0.0.1:${port}/`);

        assert.strictEqual(res.data.headers['x-poisoned'], undefined);
        assert.strictEqual(res.data.headers.authorization, undefined);
      } finally {
        await stop(server);
      }
    });

    // Same gadget through the per-method header bucket (headers.post).
    it('polluted Object.prototype.post must not inject headers into POST requests', async function () {
      this.timeout(10000);
      Object.prototype.post = { 'X-Poisoned': 'yes' };

      const server = await startServer();
      try {
        const { port } = server.address();
        const res = await axios.post(`http://127.0.0.1:${port}/`, { a: 1 });

        assert.strictEqual(res.data.method, 'POST');
        assert.strictEqual(res.data.headers['x-poisoned'], undefined);
      } finally {
        await stop(server);
      }
    });

    // Methods without a default header bucket (e.g. options) were flattened
    // from a direct `headers[config.method]` read in Axios#request.
    it('polluted Object.prototype.options must not inject headers into OPTIONS requests', async function () {
      this.timeout(10000);
      Object.prototype.options = { 'X-Poisoned': 'yes' };

      const server = await startServer();
      try {
        const { port } = server.address();
        const res = await axios.options(`http://127.0.0.1:${port}/`);

        assert.strictEqual(res.data.method, 'OPTIONS');
        assert.strictEqual(res.data.headers['x-poisoned'], undefined);
      } finally {
        await stop(server);
      }
    });
  });

});

describe("GHSA-7q8q-rj6j-mhjq nested option and Symbol gadgets", function () {
  const pollutedKeys = [
    "username",
    "password",
    "serialize",
    "encode",
    "data",
    "auth",
    "proxy",
    "paramsSerializer",
  ];

  // Inject a value onto Object.prototype the way a separate prototype-pollution
  // bug would. `writable: true` keeps ordinary assignments (`obj.data = x`) on
  // plain objects working while the pollution is active.
  function pollute(key, value) {
    Object.defineProperty(Object.prototype, key, {
      value: value,
      writable: true,
      configurable: true,
    });
  }

  function cleanup() {
    pollutedKeys.forEach(function (key) {
      delete Object.prototype[key];
    });
    delete Object.prototype[Symbol.iterator];
    delete Object.prototype[Symbol.toStringTag];
  }

  function startServer(handler) {
    return new Promise(function (resolve, reject) {
      const server = http.createServer(handler);
      server.once("error", reject);
      server.listen(0, "127.0.0.1", function () {
        resolve(server);
      });
    });
  }

  function stopServer(server) {
    return new Promise(function (resolve) {
      if (!server) {
        return resolve();
      }
      server.close(function () {
        resolve();
      });
    });
  }

  function echoServer() {
    return startServer(function (req, res) {
      res.setHeader("Content-Type", "application/json");
      res.end(
        JSON.stringify({
          authorization: req.headers.authorization || null,
          url: req.url,
        }),
      );
    });
  }

  afterEach(cleanup);

  describe("utils", function () {
    it("getSafeProp should ignore values injected onto Object.prototype", function () {
      pollute("username", "inherited-user");

      class Credentials {
        get username() {
          return "from-class";
        }
      }

      assert.strictEqual(utils.getSafeProp({}, "username"), undefined);
      assert.strictEqual(utils.hasOwnInPrototypeChain({}, "username"), false);
      assert.strictEqual(utils.getSafeProp({ username: "own" }, "username"), "own");
      assert.strictEqual(
        utils.getSafeProp(Object.create({ username: "template" }), "username"),
        "template",
      );
      assert.strictEqual(utils.getSafeProp(new Credentials(), "username"), "from-class");
      assert.strictEqual(utils.getSafeProp(null, "username"), undefined);
      assert.strictEqual(utils.getSafeProp(undefined, "username"), undefined);
    });

    it("should ignore inherited symbol properties when validating plain Object", function () {
      Object.prototype[Symbol.iterator] = function* () {
        yield ["x-injected", "yes"];
      };
      Object.prototype[Symbol.toStringTag] = "Custom";

      assert.strictEqual(utils.isPlainObject({}), true);
      assert.strictEqual(utils.isPlainObject(Object.create(null)), true);
      assert.strictEqual(utils.isPlainObject([]), false);
      assert.strictEqual(
        utils.isPlainObject({
          [Symbol.iterator]: function* () {
            yield ["x-own", "yes"];
          },
        }),
        false,
      );
      assert.strictEqual(utils.isPlainObject({ [Symbol.toStringTag]: "Custom" }), false);
    });

    it("should treat an object with a genuinely inherited iterator as non-plain", function () {
      const proto = Object.create(null);
      proto[Symbol.iterator] = function* () {
        yield ["x", "1"];
      };

      assert.strictEqual(utils.isPlainObject(Object.create(proto)), false);
    });

    it("should not read polluted Object.prototype iterator accessors for safe iterable checks", function () {
      let accessed = false;

      Object.defineProperty(Object.prototype, Symbol.iterator, {
        configurable: true,
        get() {
          accessed = true;
          throw new Error("polluted iterator accessor");
        },
      });

      assert.strictEqual(utils.isSafeIterable({}), false);
      assert.strictEqual(utils.isPlainObject({}), true);
      assert.strictEqual(accessed, false);
      assert.strictEqual(utils.isSafeIterable([]), true);
      assert.strictEqual(utils.isSafeIterable(new Map()), true);
    });

    it("should stop safe prototype-chain reads on cyclic Proxy prototypes", function () {
      let calls = 0;
      let proxy;
      proxy = new Proxy(
        {},
        {
          getPrototypeOf() {
            calls += 1;
            if (calls > 5) {
              throw new Error("cycled");
            }
            return proxy;
          },
        },
      );

      assert.strictEqual(utils.hasOwnInPrototypeChain(proxy, "missing"), false);
      assert.strictEqual(utils.getSafeProp(proxy, "missing"), undefined);
      assert.ok(calls <= 2, "prototype walk should stop on a cycle, got " + calls + " calls");
    });
  });

  describe("buildURL / getUri", function () {
    it("should ignore inherited serializer options", function () {
      let serializeInvoked = false;
      let encodeInvoked = false;

      pollute("serialize", function () {
        serializeInvoked = true;
        return "inherited=1";
      });
      pollute("encode", function () {
        encodeInvoked = true;
        return "inherited";
      });

      assert.strictEqual(buildURL("/foo", { value: "a b" }, {}), "/foo?value=a+b");
      assert.strictEqual(buildURL("/foo", { value: "a b" }), "/foo?value=a+b");
      assert.strictEqual(serializeInvoked, false);
      assert.strictEqual(encodeInvoked, false);
    });

    it("should still honor own serializer options", function () {
      pollute("serialize", function () {
        return "inherited=1";
      });

      assert.strictEqual(
        buildURL("/foo", { value: "a b" }, {
          serialize: function () {
            return "own=1";
          },
        }),
        "/foo?own=1",
      );
    });

    it("should ignore inherited nested serializer fields in getUri", function () {
      let serializeInvoked = false;

      pollute("serialize", function () {
        serializeInvoked = true;
        return "inherited=1";
      });

      assert.strictEqual(
        axios.getUri({
          url: "/foo",
          params: { value: "a b" },
          paramsSerializer: {},
        }),
        "/foo?value=a+b",
      );
      assert.strictEqual(serializeInvoked, false);
    });
  });

  describe("Axios method aliases", function () {
    it("should ignore inherited data for bodyless method helpers", function () {
      pollute("data", "inherited-body");

      return Promise.all(
        ["delete", "get", "head", "options"].map(function (method) {
          let seenData = "unset";

          return axios[method]("/test", {
            adapter: function (config) {
              seenData = config.data;

              return Promise.resolve({
                data: null,
                status: 200,
                statusText: "OK",
                headers: {},
                config: config,
                request: {},
              });
            },
          }).then(function () {
            assert.strictEqual(seenData, undefined, method + " sent an inherited body");
          });
        }),
      );
    });

    it("should still send own data for bodyless method helpers", function () {
      pollute("data", "inherited-body");

      let seenData;

      return axios
        .delete("/test", {
          data: "own-body",
          adapter: function (config) {
            seenData = config.data;

            return Promise.resolve({
              data: null,
              status: 200,
              statusText: "OK",
              headers: {},
              config: config,
              request: {},
            });
          },
        })
        .then(function () {
          assert.strictEqual(seenData, "own-body");
        });
    });
  });

  describe("AxiosHeaders", function () {
    it("should not use inherited Symbol.iterator as a key-value source object", function () {
      Object.prototype[Symbol.iterator] = function* () {
        yield ["x-app", "changed"];
        yield ["x-injected", "yes"];
      };

      const headers = new AxiosHeaders({
        "x-app": "safe",
      });

      assert.strictEqual(headers.get("x-app"), "safe");
      assert.strictEqual(headers.get("x-injected"), undefined);
    });

    it("should not read polluted Object.prototype Symbol.iterator accessors", function () {
      let accessed = false;

      Object.defineProperty(Object.prototype, Symbol.iterator, {
        configurable: true,
        get() {
          accessed = true;
          throw new Error("polluted iterator accessor");
        },
      });

      const headers = new AxiosHeaders({
        "x-app": "safe",
      });

      assert.strictEqual(headers.get("x-app"), "safe");
      assert.strictEqual(accessed, false);
    });

    it("should keep plain-object headers when Object.prototype Symbol.toStringTag is polluted", function () {
      Object.prototype[Symbol.toStringTag] = "Custom";

      const headers = new AxiosHeaders({
        Authorization: "Bearer VALID",
      });

      assert.strictEqual(headers.get("authorization"), "Bearer VALID");
    });

    it("should not consume an inherited Symbol.iterator for non-plain header sources", function () {
      Object.prototype[Symbol.iterator] = function* () {
        yield ["x-injected", "yes"];
        yield ["authorization", "Bearer CHANGED"];
      };

      class HeaderBag {
        constructor() {
          this["authorization"] = "Bearer VALID";
        }
      }

      const fromClass = new AxiosHeaders(new HeaderBag());
      assert.strictEqual(fromClass.get("x-injected"), undefined);
      assert.notStrictEqual(fromClass.get("authorization"), "Bearer CHANGED");

      const created = Object.create({ "x-app": "safe" });
      created["authorization"] = "Bearer VALID";
      const fromCreate = new AxiosHeaders(created);
      assert.strictEqual(fromCreate.get("x-injected"), undefined);
      assert.notStrictEqual(fromCreate.get("authorization"), "Bearer CHANGED");
    });
  });

  describe("http adapter", function () {
    it("should ignore inherited nested auth and paramsSerializer fields", async function () {
      const server = await echoServer();

      pollute("username", "inherited-user");
      pollute("password", "inherited-pass");
      pollute("serialize", function () {
        return "inherited=1";
      });

      try {
        const response = await axios.get(
          "http://127.0.0.1:" + server.address().port + "/demo",
          {
            auth: {},
            params: { value: "a b" },
            paramsSerializer: {},
          },
        );

        assert.deepStrictEqual(response.data, {
          authorization: "Basic Og==",
          url: "/demo?value=a+b",
        });
      } finally {
        cleanup();
        await stopServer(server);
      }
    });

    it("should still send own nested auth fields", async function () {
      const server = await echoServer();

      pollute("password", "inherited-pass");

      try {
        const response = await axios.get(
          "http://127.0.0.1:" + server.address().port + "/demo",
          {
            auth: { username: "user" },
          },
        );

        assert.strictEqual(
          response.data.authorization,
          "Basic " + Buffer.from("user:").toString("base64"),
        );
      } finally {
        cleanup();
        await stopServer(server);
      }
    });

    it("should ignore an inherited auth object", async function () {
      const server = await echoServer();

      pollute("auth", { username: "attacker", password: "exfil" });

      try {
        const response = await axios.get(
          "http://127.0.0.1:" + server.address().port + "/demo",
        );

        assert.strictEqual(response.data.authorization, null);
      } finally {
        cleanup();
        await stopServer(server);
      }
    });

    it("should ignore an inherited paramsSerializer function", async function () {
      const server = await echoServer();
      let serializerInvoked = false;

      pollute("paramsSerializer", function () {
        serializerInvoked = true;
        return "inherited=1";
      });

      try {
        const response = await axios.get(
          "http://127.0.0.1:" + server.address().port + "/demo",
          {
            params: { value: "a b" },
          },
        );

        assert.strictEqual(serializerInvoked, false);
        assert.strictEqual(response.data.url, "/demo?value=a+b");
      } finally {
        cleanup();
        await stopServer(server);
      }
    });

    it("should ignore inherited proxy when http adapter receives a plain config", async function () {
      const proxyEnvKeys = ["http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY"];
      const originalProxyEnv = Object.create(null);
      let proxyServer;
      let target;
      let proxyHits = 0;
      let targetHits = 0;

      proxyEnvKeys.forEach(function (key) {
        originalProxyEnv[key] = process.env[key];
        delete process.env[key];
      });

      try {
        proxyServer = await startServer(function (req, res) {
          proxyHits += 1;
          res.setHeader("Content-Type", "application/json");
          res.end(JSON.stringify({ via: "proxy", url: req.url }));
        });

        target = await startServer(function (req, res) {
          targetHits += 1;
          res.setHeader("Content-Type", "application/json");
          res.end(JSON.stringify({ via: "target", url: req.url }));
        });

        pollute("proxy", {
          protocol: "http",
          host: "127.0.0.1",
          port: proxyServer.address().port,
        });

        const response = await httpAdapter({
          method: "get",
          url: "http://127.0.0.1:" + target.address().port + "/direct",
          headers: {},
          maxRedirects: 0,
          maxContentLength: -1,
          maxBodyLength: -1,
          timeout: 0,
        });
        const data = JSON.parse(response.data);

        assert.strictEqual(proxyHits, 0);
        assert.strictEqual(targetHits, 1);
        assert.deepStrictEqual(data, { via: "target", url: "/direct" });
      } finally {
        cleanup();

        proxyEnvKeys.forEach(function (key) {
          if (originalProxyEnv[key] === undefined) {
            delete process.env[key];
          } else {
            process.env[key] = originalProxyEnv[key];
          }
        });

        await stopServer(target);
        await stopServer(proxyServer);
      }
    });

    it("should ignore inherited paramsSerializer when http adapter receives a plain config", async function () {
      let server;
      let serializerInvoked = false;

      pollute("paramsSerializer", function () {
        serializerInvoked = true;
        return "inherited=1";
      });

      try {
        server = await startServer(function (req, res) {
          res.setHeader("Content-Type", "application/json");
          res.end(JSON.stringify({ url: req.url }));
        });

        const response = await httpAdapter({
          method: "get",
          url: "http://127.0.0.1:" + server.address().port + "/direct",
          headers: {},
          params: { value: "a b" },
          proxy: false,
          maxRedirects: 0,
          maxContentLength: -1,
          maxBodyLength: -1,
          timeout: 0,
        });
        const data = JSON.parse(response.data);

        assert.strictEqual(serializerInvoked, false);
        assert.deepStrictEqual(data, { url: "/direct?value=a+b" });
      } finally {
        cleanup();
        await stopServer(server);
      }
    });

    it("should not use inherited Symbol.iterator for request or response headers", async function () {
      let capturedHeaders;
      const stubTransport = {
        request(options, handleResponse) {
          capturedHeaders = Object.assign({}, options.headers);
          const req = new EventEmitter();
          req.write = function () {
            return true;
          };
          req.setTimeout = function () {};
          req.destroy = function () {};
          req.end = function () {
            const res = new stream.Readable({ read() {} });
            res.statusCode = 200;
            res.statusMessage = "OK";
            res.headers = { "x-server": "real" };
            res.rawHeaders = [];
            res.req = req;
            process.nextTick(function () {
              handleResponse(res);
              res.push(null);
            });
          };
          return req;
        },
      };

      try {
        Object.prototype[Symbol.iterator] = function* () {
          yield ["X-Injected", "yes"];
          yield ["Authorization", "Bearer CHANGED"];
        };

        const response = await axios.get("http://stub.invalid/", {
          headers: {
            Authorization: "Bearer VALID_USER_TOKEN",
            "X-App": "safe",
          },
          transport: stubTransport,
          maxRedirects: 0,
        });

        assert.ok(capturedHeaders, "transport was not invoked");
        assert.strictEqual(capturedHeaders["X-App"], "safe");
        assert.strictEqual(
          capturedHeaders.Authorization || capturedHeaders.authorization,
          "Bearer VALID_USER_TOKEN",
        );
        assert.strictEqual(capturedHeaders["X-Injected"] || capturedHeaders["x-injected"], undefined);
        assert.strictEqual(response.headers.get("x-server"), "real");
        assert.strictEqual(response.headers.get("x-injected"), undefined);
      } finally {
        cleanup();
      }
    });
  });
});

describe("GHSA-pf86-5x62-jrwf config value gadgets", function () {
  const pollutedKeys = [
    "transport",
    "transformRequest",
    "transformResponse",
    "adapter",
    "headers",
    "formSerializer",
    "env",
    "transitional",
    "responseType",
    "response",
  ];

  // Inject a value onto Object.prototype the way a separate prototype-pollution
  // bug would. `writable: true` keeps ordinary assignments on plain objects
  // working while the pollution is active.
  function pollute(key, value) {
    Object.defineProperty(Object.prototype, key, {
      value: value,
      writable: true,
      configurable: true,
    });
  }

  function cleanup() {
    pollutedKeys.forEach(function (key) {
      delete Object.prototype[key];
    });
  }

  function startServer(handler) {
    return new Promise(function (resolve, reject) {
      const server = http.createServer(handler);
      server.once("error", reject);
      server.listen(0, "127.0.0.1", function () {
        resolve(server);
      });
    });
  }

  function stopServer(server) {
    return new Promise(function (resolve) {
      if (!server) {
        return resolve();
      }
      server.close(function () {
        resolve();
      });
    });
  }

  afterEach(cleanup);

  describe("mergeConfig with defaults", function () {
    it("should not let polluted transformRequest/transformResponse replace the defaults", function () {
      const hijack = function () {
        return "hijacked";
      };

      pollute("transformRequest", hijack);
      pollute("transformResponse", hijack);

      try {
        const result = mergeConfig(defaults, { url: "/a" });

        assert.notStrictEqual(result.transformRequest, hijack);
        assert.notStrictEqual(result.transformResponse, hijack);
        assert.deepStrictEqual(result.transformRequest, defaults.transformRequest);
        assert.deepStrictEqual(result.transformResponse, defaults.transformResponse);
      } finally {
        cleanup();
      }
    });

    it("should not let a polluted adapter replace the default adapter", function () {
      const hijack = function () {
        return Promise.resolve({ data: "hijacked" });
      };

      pollute("adapter", hijack);

      try {
        const result = mergeConfig(defaults, { url: "/a" });

        assert.notStrictEqual(result.adapter, hijack);
        assert.deepStrictEqual(result.adapter, defaults.adapter);
      } finally {
        cleanup();
      }
    });

    it("should not merge polluted headers into the default headers", function () {
      pollute("headers", { "X-Injected": "yes" });

      try {
        const result = mergeConfig(defaults, { url: "/a" });

        assert.strictEqual(
          Object.prototype.hasOwnProperty.call(result.headers, "X-Injected"),
          false
        );
        assert.strictEqual(
          result.headers.common.Accept,
          defaults.headers.common.Accept
        );
      } finally {
        cleanup();
      }
    });

    it("should still prefer own request config values over defaults", function () {
      const ownTransform = function (data) {
        return data;
      };
      const result = mergeConfig(defaults, {
        url: "/a",
        transformRequest: ownTransform,
        headers: { "X-Own": "yes" },
      });

      assert.strictEqual(result.transformRequest, ownTransform);
      assert.strictEqual(result.headers["X-Own"], "yes");
      assert.deepStrictEqual(result.transformResponse, defaults.transformResponse);
    });
  });

  describe("defaults.transformRequest", function () {
    it("should ignore a polluted formSerializer for urlencoded payloads", function () {
      let visitorInvoked = false;

      pollute("formSerializer", {
        visitor: function () {
          visitorInvoked = true;
          this.append("injected", "yes");
          return false;
        },
      });

      try {
        const headers = new AxiosHeaders();
        headers.setContentType("application/x-www-form-urlencoded");

        const result = defaults.transformRequest[0].call(
          {},
          { foo: "bar" },
          headers
        );

        assert.strictEqual(visitorInvoked, false);
        assert.strictEqual(result, "foo=bar");
      } finally {
        cleanup();
      }
    });

    it("should still honor an own formSerializer", function () {
      const headers = new AxiosHeaders();
      headers.setContentType("application/x-www-form-urlencoded");

      const result = defaults.transformRequest[0].call(
        { formSerializer: { dots: true } },
        { a: { b: "c" } },
        headers
      );

      assert.strictEqual(result, "a.b=c");
    });

    it("should ignore a polluted env.FormData for multipart payloads", function () {
      let hijackConstructed = false;

      function HijackFormData() {
        hijackConstructed = true;
      }
      HijackFormData.prototype.append = function () {};

      pollute("env", { FormData: HijackFormData });

      try {
        const headers = new AxiosHeaders();
        headers.setContentType("multipart/form-data");

        const result = defaults.transformRequest[0].call(
          {},
          { foo: "bar" },
          headers
        );

        assert.strictEqual(hijackConstructed, false);
        assert.strictEqual(result instanceof HijackFormData, false);
      } finally {
        cleanup();
      }
    });
  });

  describe("defaults.transformResponse", function () {
    it("should ignore a polluted transitional that disables JSON parsing", function () {
      pollute("transitional", {
        silentJSONParsing: true,
        forcedJSONParsing: false,
      });

      try {
        const result = defaults.transformResponse[0].call({}, '{"role":"user"}');

        assert.deepStrictEqual(result, { role: "user" });
      } finally {
        cleanup();
      }
    });

    it("should ignore a polluted responseType", function () {
      pollute("responseType", "text");

      try {
        const result = defaults.transformResponse[0].call({}, '{"role":"user"}');

        assert.deepStrictEqual(result, { role: "user" });
      } finally {
        cleanup();
      }
    });

    it("should not attach a polluted response to JSON parse errors", function () {
      const pollutedResponse = { status: 200, data: "attacker" };

      pollute("response", pollutedResponse);

      try {
        assert.throws(
          function () {
            defaults.transformResponse[0].call(
              {
                responseType: "json",
                transitional: {
                  silentJSONParsing: false,
                  forcedJSONParsing: true,
                },
              },
              "{invalid json"
            );
          },
          function (err) {
            return (
              err.code === "ERR_BAD_RESPONSE" &&
              !Object.prototype.hasOwnProperty.call(err, "response")
            );
          }
        );
      } finally {
        cleanup();
      }
    });
  });

  describe("http adapter", function () {
    it("should not route requests through a polluted transport", async function () {
      let hijackedAuth = null;
      let server;

      try {
        server = await startServer(function (req, res) {
          res.setHeader("Content-Type", "application/json");
          res.end(JSON.stringify({ authorization: req.headers.authorization || null }));
        });

        pollute("transport", {
          request: function (options, handleResponse) {
            hijackedAuth = options.auth || "(none)";
            return http.request(options, handleResponse);
          },
        });

        const response = await axios.get(
          "http://127.0.0.1:" + server.address().port + "/api/users",
          {
            auth: { username: "svc_account", password: "hunter2" },
          }
        );

        assert.strictEqual(hijackedAuth, null);
        assert.strictEqual(
          response.data.authorization,
          "Basic " + Buffer.from("svc_account:hunter2").toString("base64")
        );
      } finally {
        cleanup();
        await stopServer(server);
      }
    });

    it("should not run polluted transformRequest/transformResponse functions", async function () {
      let requestTransformInvoked = false;
      let responseTransformInvoked = false;
      let server;

      try {
        server = await startServer(function (req, res) {
          let body = "";
          req.on("data", function (chunk) {
            body += chunk;
          });
          req.on("end", function () {
            res.setHeader("Content-Type", "application/json");
            res.end(JSON.stringify({ received: body }));
          });
        });

        pollute("transformRequest", function () {
          requestTransformInvoked = true;
          return '{"tampered":true}';
        });
        pollute("transformResponse", function () {
          responseTransformInvoked = true;
          return { tampered: true };
        });

        const response = await axios.post(
          "http://127.0.0.1:" + server.address().port + "/",
          { role: "user" }
        );

        assert.strictEqual(requestTransformInvoked, false);
        assert.strictEqual(responseTransformInvoked, false);
        assert.deepStrictEqual(response.data, { received: '{"role":"user"}' });
      } finally {
        cleanup();
        await stopServer(server);
      }
    });

    it("should ignore a polluted env.Blob when decoding data: URIs", async function () {
      let hijackConstructed = false;

      function HijackBlob() {
        hijackConstructed = true;
      }

      pollute("env", { Blob: HijackBlob });

      try {
        let response;

        try {
          response = await httpAdapter({
            method: "get",
            url: "data:text/plain;base64,SGVsbG8=",
            headers: {},
            responseType: "blob",
            maxContentLength: -1,
            maxBodyLength: -1,
          });
        } catch (err) {
          // Runtimes without a global Blob reject with "Blob is not supported"
          // once the polluted constructor is no longer picked up.
          assert.ok(/Blob is not supported/.test(err.message), err.message);
        }

        assert.strictEqual(hijackConstructed, false);
        if (response) {
          assert.strictEqual(response.data instanceof HijackBlob, false);
        }
      } finally {
        cleanup();
      }
    });
  });
});
