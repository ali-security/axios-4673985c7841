// https://github.com/axios/axios/security/advisories/GHSA-jr5f-v2jv-69x6
// CVE-2025-27152: an absolute request URL overrides the configured `baseURL`,
// which allows SSRF and leaks credentials configured on the instance.
// `allowAbsoluteUrls: false` must keep every request on `baseURL`.

import axios from '../../../index.js';
import http from 'http';
import assert from 'assert';
import {createRequire} from 'module';

const require = createRequire(import.meta.url);

const GOOD_PORT = 4676;
const BAD_PORT = 4677;
const GOOD_BASE_URL = 'http://localhost:' + String(GOOD_PORT);
const BAD_URL = 'http://localhost:' + String(BAD_PORT) + '/steal';

describe('Absolute URL overriding baseURL (CVE-2025-27152)', () => {
    let goodServer, badServer, goodRequests, badRequests;

    beforeEach((done) => {
        goodRequests = [];
        badRequests = [];
        goodServer = http.createServer(function (req, res) {
            goodRequests.push({url: req.url, headers: req.headers});
            res.setHeader('Connection', 'close');
            res.end('good');
        });
        badServer = http.createServer(function (req, res) {
            badRequests.push({url: req.url, headers: req.headers});
            res.setHeader('Connection', 'close');
            res.end('bad');
        });
        goodServer.listen(GOOD_PORT, () => {
            badServer.listen(BAD_PORT, () => done());
        });
    });

    afterEach((done) => {
        goodServer.close(() => {
            badServer.close(() => done());
        });
    });

    it('should keep an absolute URL on baseURL when allowAbsoluteUrls is false on the instance', async () => {
        const instance = axios.create({
            baseURL: GOOD_BASE_URL,
            allowAbsoluteUrls: false,
            headers: {Authorization: 'Bearer secret-token'}
        });

        const response = await instance.get(BAD_URL);

        assert.strictEqual(response.data, 'good');
        assert.strictEqual(badRequests.length, 0, 'request (and its credentials) leaked to the absolute URL host');
        assert.strictEqual(goodRequests.length, 1);
        assert.strictEqual(goodRequests[0].url, '/' + BAD_URL);
        assert.strictEqual(goodRequests[0].headers.authorization, 'Bearer secret-token');
    });

    it('should keep an absolute URL on baseURL when allowAbsoluteUrls is false in the request config', async () => {
        const response = await axios.get(BAD_URL, {
            baseURL: GOOD_BASE_URL,
            allowAbsoluteUrls: false
        });

        assert.strictEqual(response.data, 'good');
        assert.strictEqual(badRequests.length, 0);
        assert.strictEqual(goodRequests[0].url, '/' + BAD_URL);
    });

    it('should keep an absolute URL on baseURL when allowAbsoluteUrls is false in instance defaults', async () => {
        const instance = axios.create({
            baseURL: GOOD_BASE_URL
        });
        instance.defaults.allowAbsoluteUrls = false;

        const response = await instance.get(BAD_URL);

        assert.strictEqual(response.data, 'good');
        assert.strictEqual(badRequests.length, 0);
        assert.strictEqual(goodRequests[0].url, '/' + BAD_URL);
    });

    it('should keep a protocol-relative URL on baseURL when allowAbsoluteUrls is false', async () => {
        const instance = axios.create({
            baseURL: GOOD_BASE_URL,
            allowAbsoluteUrls: false
        });

        const response = await instance.get('//localhost:' + String(BAD_PORT) + '/steal');

        assert.strictEqual(response.data, 'good');
        assert.strictEqual(badRequests.length, 0);
        assert.strictEqual(goodRequests[0].url, '/localhost:' + String(BAD_PORT) + '/steal');
    });

    it('should resolve getUri against baseURL when allowAbsoluteUrls is false', () => {
        const instance = axios.create({
            baseURL: GOOD_BASE_URL,
            allowAbsoluteUrls: false
        });

        assert.strictEqual(instance.getUri({url: BAD_URL}), GOOD_BASE_URL + '/' + BAD_URL);
    });

    it('should keep an absolute URL on baseURL when allowAbsoluteUrls is false with the CommonJS build', async () => {
        // `require('axios')` in Node.js resolves to the prebuilt CommonJS bundle
        const axiosCJS = require('../../../dist/node/axios.cjs');

        const instance = axiosCJS.create({
            baseURL: GOOD_BASE_URL,
            allowAbsoluteUrls: false
        });

        const response = await instance.get(BAD_URL);

        assert.strictEqual(response.data, 'good');
        assert.strictEqual(badRequests.length, 0);
        assert.strictEqual(goodRequests[0].url, '/' + BAD_URL);
        assert.strictEqual(instance.getUri({url: BAD_URL}), GOOD_BASE_URL + '/' + BAD_URL);
    });

    it('should still let an absolute URL override baseURL by default', async () => {
        const instance = axios.create({
            baseURL: GOOD_BASE_URL
        });

        const response = await instance.get(BAD_URL);

        assert.strictEqual(response.data, 'bad');
        assert.strictEqual(goodRequests.length, 0);
        assert.strictEqual(badRequests.length, 1);
        assert.strictEqual(response.config.allowAbsoluteUrls, true);
    });
});
