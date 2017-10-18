var Config = require('keycloak-auth-utils').Config,
    GrantManager = require('keycloak-auth-utils').GrantManager,
    Keycloak = require('keycloak-connect'),
    uuid = require('uuid'),
    URLUtil = require('url');



function Strategy(options, verify) {
    this.callbackUrl = options.callbackURL;
    this.config = new Config(options.keycloakConfig);
    this.grantManager = new GrantManager(this.config);
    this.validRedirectsHosts = options.validRedirectsHosts || [];
    this.name = 'keycloak';
    this.verify = verify;
}

Strategy.SESSION_KEY = 'keycloak-token';

Strategy.prototype.authenticate = function (req, options) {

    var self = this;

    if (req.query && req.query.error) {
      return this.fail(req.query.error);
    }

    function verified(err, user, info) {
        if (err) {
            return self.error(err);
        }
        if (!user) {
            return self.fail(info);
        }
        self.success(user, info);
    }

    this.getGrant(req)
      .then(grant => {
        self.verify(grant.access_token.content, grant.refresh_token.content, grant.id_token.content, verified);
      })
      .catch(() => {
        if (req.query.auth_callback) {
            var sessionId = req.session ? req.session.id : undefined;
            this.getGrantFromCode(req, req.query.code, sessionId)
              .then(grant => {
                  if (req.session) {
                      req.session[Strategy.SESSION_KEY] = grant.__raw;
                  }
                  self.redirect(self.cleanUrl(req));
              })
              .catch((err) => {
                return self.error(err);
              })
            ;
        } else {
            var loginURL = this.loginUrl(uuid.v4(), this.getRedirectURL(req));
            this.redirect(loginURL);
        }
      })
    ;

};

Strategy.prototype.getGrantFromCode = function (req, code, sessionId) {
    return new Promise((resolve, reject) => {
      this.grantManager.obtainFromCode(req, code, sessionId)
        .then(resolve)
        .catch(reject)
      ;
    });
};

Strategy.prototype.cleanUrl = function (req) {
    var urlObj = {
        pathname: req.path,
        query: req.query
    };
    delete urlObj.query.code;
    delete urlObj.query.auth_callback;
    delete urlObj.query.state;

    return URLUtil.format(urlObj);
};

Strategy.prototype.getRedirectURL = function (req) {

    var host = req.hostname;
    var headerHost = req.headers.host.split(':');
    var port = headerHost[1] || '';
    var protocol = req.protocol;
    if (req.headers['x-forwarded-proto'] === 'https') {
        protocol = 'https';
    }
    var callbackUrl = this.callbackUrl;
    if (callbackUrl[0] !== '/') {
        callbackUrl = '/' + callbackUrl;
    }
    var redirectUrl = protocol + '://' + host + (port === '' ? '' : ':' + port) + callbackUrl + '?auth_callback=1';
    if (req.session) {
        req.session.auth_redirect_uri = redirectUrl;
        try {
            if (req.headers.referer && this.validRedirectsHosts.indexOf(URLUtil.parse(req.headers.referer).hostname) > -1) {
                req.session.returnTo = req.headers.referer;
            }
        } catch (e) { }
    }
    return redirectUrl;
};

Strategy.prototype.getGrant = function (req) {
  return new Promise((resolve, reject) => {

    var grantData = req.session[Strategy.SESSION_KEY];
    if (typeof grantData === 'string') {
      grantData = JSON.parse(grantData);
    }

    if (grantData && !grantData.error) {
      this.grantManager.createGrant(JSON.stringify(grantData))
        .then( grant => {
          this.grantManager.ensureFreshness(grant)
            .then(grant => {
              resolve(grant);
            })
          ;
        })
        .catch(reject)
      ;

    } else {
      reject();
    }

  });
};

Strategy.prototype.loginUrl = Keycloak.prototype.loginUrl;
Strategy.prototype.logoutUrl = Keycloak.prototype.logoutUrl;

exports = module.exports = Strategy;
exports.Strategy = Strategy;
