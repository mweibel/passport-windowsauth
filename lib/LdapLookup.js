var ldap = require('ldapjs');
var debug = require('debug')('passport-windowsauth:ldaplookup');

var LdapLookup = module.exports = function(options){
  this._options = options;

  this._search_query = options.search_query ||
    '(&(objectclass=user)(|(sAMAccountName={0})(UserPrincipalName={0})))';

  this._client = options.client ? options.client : ldap.createClient({
    url:             options.url,
    maxConnections:  options.maxConnections || 10,
    bindDN:          options.bindDN,
    bindCredentials: options.bindCredentials,
    tlsOptions:      options.tlsOptions,
    reconnect:       options.reconnect
  });

  this._client.on('error', function(e){
    debug('error', e);
    console.log('LDAP connection error:', e);
  });

  if (options.client) {
    this.clientConnected = true;
    return;
  }

  this._queue = [];
  var self = this;

  debug('binding tryout');

  this._client.bind(options.bindDN, options.bindCredentials, function(err) {
    debug('bound', err);
    if(err){
        return console.log("Error binding to LDAP", 'dn: ' + err.dn + '\n code: ' + err.code + '\n message: ' + err.message);
    }
    self.clientConnected = true;
    self._queue.forEach(function (cb) { cb(); });
  });
};

LdapLookup.prototype.search = function (username, callback) {
  var self = this;
  debug('search', username);
  function exec(){
    var opts = {
      scope: 'sub',
      filter: self._search_query.replace(/\{0\}/ig, username)
    };
    self._client.search(self._options.base, opts, function(err, res){
      debug('searched', err);
      var entries = [];
      res.on('searchEntry', function(entry) {
        debug('searchEntry', entry);
        entries.push(entry);
      });
      res.on('error', function(err) {
        debug('error', err);
        callback(err);
      });
      res.on('end', function() {
        debug('end', entries.length);
        if(entries.length === 0) return callback(null, null);
        callback(null, entries[0].object);
      });
    });
  }

  if(this.clientConnected){
    exec();
  } else {
    this._queue.push(exec);
  }
};
