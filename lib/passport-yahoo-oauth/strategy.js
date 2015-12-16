/**
 * Module dependencies.
 */
var util = require('util')
  , OAuthStrategy = require('passport-oauth').OAuthStrategy
  , InternalOAuthError = require('passport-oauth').InternalOAuthError;


/**
 * `Strategy` constructor.
 *
 * The Yahoo authentication strategy authenticates requests by delegating to
 * Yahoo using the OAuth protocol.
 *
 * Applications must supply a `verify` callback which accepts a `token`,
 * `tokenSecret` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `consumerKey`     identifies client to Yahoo
 *   - `consumerSecret`  secret used to establish ownership of the consumer key
 *   - `callbackURL`     URL to which Yahoo will redirect the user after obtaining authorization
 *
 * Examples:
 *
 *     passport.use(new YahooStrategy({
 *         consumerKey: '123-456-789',
 *         consumerSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/yahoo/callback'
 *       },
 *       function(token, tokenSecret, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  options.requestTokenURL = options.requestTokenURL || 'https://api.login.yahoo.com/oauth/v2/get_request_token';
  options.accessTokenURL = options.accessTokenURL || 'https://api.login.yahoo.com/oauth/v2/get_token';
  options.userAuthorizationURL = options.userAuthorizationURL || 'https://api.login.yahoo.com/oauth/v2/request_auth';
  options.sessionKey = options.sessionKey || 'oauth:yahoo';

  OAuthStrategy.call(this, options, verify);
  this.name = 'yahoo';
}

/**
 * Inherit from `OAuthStrategy`.
 */
util.inherits(Strategy, OAuthStrategy);

/**
 * Retrieve user profile from Yahoo.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `id`
 *   - `displayName`
 *
 * @param {String} token
 * @param {String} tokenSecret
 * @param {Object} params
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(token, tokenSecret, params, done) {

  var path = yql('select * from social.profile(0) where guid=me');

  this._oauth.get(path, token, tokenSecret, function (err, body, res) {
    if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }

    try {
      var json = JSON.parse(body).query.results;

      var profile = { provider: 'yahoo' };
      profile.id = json.profile.guid;
      profile.displayName = json.profile.givenName + ' ' + json.profile.familyName;
      profile.name = { familyName: json.profile.familyName,
                       givenName: json.profile.givenName };

      if (json.profile.image && json.profile.image.imageUrl) {
	      profile.photos = [{value: json.profile.image.imageUrl}];
      }
      if (json.profile.emails && json.profile.emails.length) {
	      profile.emails = json.profile.emails.map(mapEmails);
      }

      profile._raw = body;
      profile._json = json;

      done(null, profile);
    } catch(e) {
      done(e);
    }
  });
}


/**
 * Use the YQL endpoint and attach a query
 * @param {String} query
 */
function yql(q) {
  return 'https://query.yahooapis.com/v1/yql?q=' + q.replace(/\s/g, '%20') + '&format=json';
}

/**
 * Given a YQL email item convert it into the standard of PassportJS
 */
function mapEmails(item) {
	return {
		value: item.handle
	};
}

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
