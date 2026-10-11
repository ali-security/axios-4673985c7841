import cookies from '../../lib/helpers/cookies';

describe('xsrf', function () {
  beforeEach(function () {
    jasmine.Ajax.install();
  });

  afterEach(function () {
    document.cookie = axios.defaults.xsrfCookieName + '=;expires=' + new Date(Date.now() - 86400000).toGMTString();
    jasmine.Ajax.uninstall();
  });

  it('should not set xsrf header if cookie is null', function (done) {
    axios('/foo');

    getAjaxRequest().then(function (request) {
      expect(request.requestHeaders[axios.defaults.xsrfHeaderName]).toEqual(undefined);
      done();
    });
  });

  it('should set xsrf header if cookie is set', function (done) {
    document.cookie = axios.defaults.xsrfCookieName + '=12345';

    axios('/foo');

    getAjaxRequest().then(function (request) {
      expect(request.requestHeaders[axios.defaults.xsrfHeaderName]).toEqual('12345');
      done();
    });
  });

  it('should not set xsrf header if xsrfCookieName is null', function (done) {
    document.cookie = axios.defaults.xsrfCookieName + '=12345';

    axios('/foo', {
      xsrfCookieName: null
    });

    getAjaxRequest().then(function (request) {
      expect(request.requestHeaders[axios.defaults.xsrfHeaderName]).toEqual(undefined);
      done();
    });
  });

  it('should not read cookies at all if xsrfCookieName is null', function (done) {
    spyOn(cookies, "read");

    axios('/foo', {
      xsrfCookieName: null
    });

    getAjaxRequest().then(function (request) {
      expect(cookies.read).not.toHaveBeenCalled();
      done();
    });
  });

  it('should not set xsrf header for cross origin', function (done) {
    document.cookie = axios.defaults.xsrfCookieName + '=12345';

    axios('http://example.com/');

    getAjaxRequest().then(function (request) {
      expect(request.requestHeaders[axios.defaults.xsrfHeaderName]).toEqual(undefined);
      done();
    });
  });

  it('should not set xsrf header for cross origin when using withCredentials', function (done) {
    document.cookie = axios.defaults.xsrfCookieName + '=12345';

    axios('http://example.com/', {
      withCredentials: true
    });

    getAjaxRequest().then(function (request) {
      expect(request.requestHeaders[axios.defaults.xsrfHeaderName]).toEqual(undefined);
      done();
    });
  });

  describe('withXSRFToken option', function(){

    it('should set xsrf header for cross origin when withXSRFToken = true', function (done) {
      const token = '12345';

      document.cookie = axios.defaults.xsrfCookieName + '=' + token;

      axios('http://example.com/', {
        withXSRFToken: true
      });

      getAjaxRequest().then(function (request) {
        expect(request.requestHeaders[axios.defaults.xsrfHeaderName]).toEqual(token);
        done();
      });
    });

    it('should not set xsrf header for the same origin when withXSRFToken = false', function (done) {
      const token = '12345';

      document.cookie = axios.defaults.xsrfCookieName + '=' + token;

      axios('/foo', {
        withXSRFToken: false
      });

      getAjaxRequest().then(function (request) {
        expect(request.requestHeaders[axios.defaults.xsrfHeaderName]).toEqual(undefined);
        done();
      });
    });

    it('should not set xsrf header for the same origin when withXSRFToken = false', function (done) {
      const token = '12345';

      document.cookie = axios.defaults.xsrfCookieName + '=' + token;

      axios('/foo', {
        withXSRFToken: false
      });

      getAjaxRequest().then(function (request) {
        expect(request.requestHeaders[axios.defaults.xsrfHeaderName]).toEqual(undefined);
        done();
      });
    });

    it('should support function resolver', (done) => {
      const token = '12345';

      document.cookie = axios.defaults.xsrfCookieName + '=' + token;

      axios('/foo', {
        withXSRFToken: (config) => config.userFlag === 'yes',
        userFlag: 'yes'
      });

      getAjaxRequest().then(function (request) {
        expect(request.requestHeaders[axios.defaults.xsrfHeaderName]).toEqual(token);
        done();
      });
    });

    it('should not set xsrf header for cross origin when the function resolver returns false', function (done) {
      document.cookie = axios.defaults.xsrfCookieName + '=12345';

      axios('http://example.com/', {
        withCredentials: true,
        withXSRFToken: (config) => config.userFlag === 'yes',
        userFlag: 'no'
      });

      getAjaxRequest().then(function (request) {
        expect(request.requestHeaders[axios.defaults.xsrfHeaderName]).toEqual(undefined);
        done();
      });
    });

    it('should set xsrf header for cross origin when using withCredentials and withXSRFToken = true', function (done) {
      document.cookie = axios.defaults.xsrfCookieName + '=12345';

      axios('http://example.com/', {
        withCredentials: true,
        withXSRFToken: true
      });

      getAjaxRequest().then(function (request) {
        expect(request.requestHeaders[axios.defaults.xsrfHeaderName]).toEqual('12345');
        done();
      });
    });

    describe('non-boolean values', function () {
      afterEach(function () {
        delete Object.prototype.withXSRFToken;
      });

      [
        ['the number 1', 1],
        ['the string "false"', 'false'],
        ['an object', {}],
        ['an array', []]
      ].forEach(function (pair) {
        it('should not set xsrf header for cross origin when withXSRFToken is ' + pair[0], function (done) {
          document.cookie = axios.defaults.xsrfCookieName + '=12345';

          axios('http://example.com/', {
            withCredentials: true,
            withXSRFToken: pair[1]
          });

          getAjaxRequest().then(function (request) {
            expect(request.requestHeaders[axios.defaults.xsrfHeaderName]).toEqual(undefined);
            done();
          });
        });
      });

      it('should not set xsrf header for cross origin when the function resolver returns a truthy non-boolean', function (done) {
        document.cookie = axios.defaults.xsrfCookieName + '=12345';

        axios('http://example.com/', {
          withXSRFToken: () => 'yes'
        });

        getAjaxRequest().then(function (request) {
          expect(request.requestHeaders[axios.defaults.xsrfHeaderName]).toEqual(undefined);
          done();
        });
      });

      it('should not set xsrf header for cross origin when Object.prototype.withXSRFToken is polluted', function (done) {
        Object.prototype.withXSRFToken = 1;
        document.cookie = axios.defaults.xsrfCookieName + '=12345';

        axios('http://example.com/', {
          withCredentials: true
        });

        getAjaxRequest().then(function (request) {
          expect(request.requestHeaders[axios.defaults.xsrfHeaderName]).toEqual(undefined);
          done();
        });
      });
    });
  });
});
