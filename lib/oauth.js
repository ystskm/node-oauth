/**
 * [oauth] oauth.js
 * 認証ルーティンの実現をサポート OAuth 1.0 / OAuth 2.0
 */
const NULL = null, TRUE = true, FALSE = false, UNDEF = undefined;
const fs = require('fs'),
    crypto = require('crypto'),
    sha1 = require('./sha1'),
    http = require('http'),
    https = require('https'),
    URL= require('url'),
    querystring = require('querystring'); 
module.exports = OAuth;
function OAuth( settings ) {
  if( !(this instanceof OAuth))
    return new OAuth( settings );
  try {
    if( typeof settings == "object" )
      this.settings = settings;
    else if( typeof settings == "string" )
      this.settings = require(settings);
    else
      throw new Error('Unresolved setting.');
  } catch(e) {
    console.error(e);
    throw e;
  }
}
OAuth.__filename = __filename; // To refer the position (Good solution!)
OAuth.Authorizer = Authorizer;
OAuth.Tokenizer = Tokenizer;
OAuth.generateCodeChallenge = function(code_challenge_method, code_verifier) {
  // https://www.authlete.com/ja/developers/pkce/
  // code_verifier の値は、[A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~" からなるランダムな文字列であり、最低43文字、最大128文字の長さが必要となります。
  // 定義されている code_challenge_method の値は、plain および S256 になります。それぞれの計算ロジックは下記のとおりです。
  // plain code_challenge = code_verifier
  // S256  code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
  let p = String(code_challenge_method).toLowerCase();
  switch(p) {
  case 's256':
    p = 'sha256';
    break;
  }
  // crypto.createHash('sha256').update(cv).digest().toString('base64')
  // https://tools.ietf.org/html/rfc7636#appendix-A
  let s = crypto.createHash(p).update(code_verifier).digest().toString('base64');
  s = s.split('=')[0];
  s = s.replace(/\+/g, '-');
  s = s.replace(/\//g, '_');
  return s;
}
OAuth.prototype.authorize = function( type ,options, callback ){
  return new Authorizer( this, type, options, callback );
};
OAuth.prototype.access = function( type ,options, callback ){
  return new Tokenizer( this, type, options, callback );
};

// ============== Authorizer ============== //
function Authorizer( oauth, type, options, callback ) {

  if( !( this instanceof Authorizer ) )
    return new Authorizer( oauth, type, options );

  const atrz = this;
  atrz.oauth = oauth;
  if(!oauth.settings[ type ]) {
    throw new Error('API Keys are not defined.');
  }
  _mixin(atrz, oauth.settings[ type ]);
  // console.log('Authorizer mixin:', oauth.settings[ type ], atrz);
  
  const opts = atrz.options = _mixin({
    signatureMethod:"HMAC-SHA1", 
    requestTokenCallback: function(er, rd) {
      if(er instanceof Error)
        throw er;
      (_arg2arr( arguments ).pop())(er, rd); // execute callback function
    }, 
    endCallback: function(er) {
      if(isFunction(callback))
        return callback(er);
      if(er)
        throw er;
    }, 
    auto: TRUE 
  }, options);
  // console.log('Goto chain ... ' + atrz.version);
  
  if(opts['auto'] !== FALSE) {
    switch(atrz.version) {
    case "1.0":
    case 1:
      _chain([ atrz.getRequestToken, opts['requestTokenCallback'], atrz.redirectToAuthorize, opts['endCallback'] ], atrz);
      break;
    case "2.0":
    case 2:
      _chain([ atrz.redirectToAuthorize, opts['endCallback'] ], atrz);
      break;
    default:
      opts.endCallback.call(atrz, new Error('Unknown version: ' + atrz.version));
    }
  } else {
    if(isFunction(callback))
      callback();
  }
  
};
Authorizer.prototype.getRequestToken= function( callback ) {
  // console.log('getRequestToken');
  const atrz = this, request_type = 'requestToken';
  const request_param = atrz[request_type], extra_param = { _nonceSize: 32 };
  // Callbacks are 1.0A related
  /*
   * if( this._authorize_callback ) extraParams["oauth_callback"]=
   * this._authorize_callback;
   */
  return atrz._performSecureRequest( "POST", request_type, request_param, extra_param, function(er, data, response) {
    if(er) {
      return callback( er );
    }
    const results = data; // querystring.parse(data); => _performSecureRequest have executed parse
    // console.log('getRequestToken._performSecureRequest result:', er, data, results);
    switch(atrz.version) {
    case "1.0":
    case 1:
      atrz.request_token = results["oauth_token"];
      atrz.request_token_secret = results["oauth_token_secret"];
      break;
    case "2.0":
    case 2:
      atrz.code = results["code"];
      break;
    }
    callback( NULL, results );
  });
};

Authorizer.prototype.redirectToAuthorize = function( callback ) {
  // console.log('redirectToAuthorize');
  const atrz = this, request_type = 'authorize';
  const request_param = atrz[request_type], extra_param = { _simpleArgs: true };
  return atrz._performSecureRequest( "GET", request_type, request_param, extra_param, (er, data, response)=>callback(er, data));
};

// ============== Tokenizer ============== //
function Tokenizer( oauth, type, options, callback ) {
  
  if( !( this instanceof Tokenizer ) )
    return new Tokenizer( oauth, type, options, callback );

  const tknz = this;
  tknz.oauth = oauth;
  tknz.type = type;
  if(!oauth.settings[ type ]) {
    throw new Error('API Keys are not defined.');
  }
  _mixin(tknz, oauth.settings[ type ]);
  // console.log('Tokenizer mixin:', oauth.settings[ type ], tknz);
  
  const opts = tknz.options = _mixin({
    signatureMethod:"HMAC-SHA1", 
    accessTokenCallback: function(er, rd) {
      if(er instanceof Error)
        throw er;
      (_arg2arr( arguments ).pop())(er, rd); // execute callback function
    }, 
    endCallback: function(er) {
      if(isFunction(callback))
        return callback(er);
      if(er)
        throw er;
    },
    auto: TRUE 
  }, options);

  if(opts['auto'] !== FALSE) {
    if(!opts['href']) {
      // "href" means the requested url from authorized page
      throw new Error(' Location Full Url or Request Token must be set to get OAuth access_token. ');
    }
    var purl = URL.parse(opts['href'], true);
    var pquery = purl.query;
    // console.log('href?', opts['href'], pquery);
    switch(tknz.version) {
    case "1.0":
    case 1:
      // Use generic key-pair transfer if value is not set yet.
      [ ['request_token', 'oauth_token'],  ['oauth_verifier', 'oauth_verifier'] ].forEach(pair=>{
        if(tknz[ pair[0] ] == NULL) { pair[1] = pair[1] || pair[0]; tknz[ pair[0] ]= pquery[ pair[1] ]; }
      });
      _chain([ tknz.getAccessToken, opts['accessTokenCallback'], opts['endCallback'] ], tknz);
      break;
    case "2.0":
    case 2:
      // Use generic key-pair transfer if value is not set yet.
      [ ['code'] ].forEach(pair=>{
        if(tknz[ pair[0] ] == NULL) { pair[1] = pair[1] || pair[0]; tknz[ pair[0] ]= pquery[ pair[1] ]; }
      });
      tknz.code = tknz.code || pquery['code'];
      _chain([ tknz.getAccessToken, opts['endCallback'] ], tknz);
      break;
    default:
      opts.endCallback.call(tknz, new Error('Unknown version: ' + tknz.version));
    }
  } else {
    if(isFunction(callback))
      callback();
  }

};

Tokenizer.prototype.getAccessToken = function( callback ) {
  // console.log('getAccessToken');
  if( !isFunction(callback) ) { callback = Function(); }
  const tknz = this, request_type = 'accessToken';
  const request_param = tknz[request_type], extra_param = { _nonceSize: 32 };
  // Callbacks are 1.0A related
  /*
   * if( this._authorize_callback ) extraParams["oauth_callback"]=
   * this._authorize_callback;
   */
  return tknz._performSecureRequest( request_param['method'] || 'POST', request_type, request_param, extra_param, function(er, data, response) {
    // same callback as refreshToken;
    if(er) {
      return callback( er );
    }
    const results = data; // querystring.parse(data); => _performSecureRequest have executed parse
    // console.log('getAccessToken._performSecureRequest result:', er, data, results);
    const headers = tknz._headers = tknz._headers || { };
    switch(tknz.version) {
    case "1.0":
    case 1:
      [ ['access_token', 'oauth_token'], ['access_token_secret', 'oauth_token_secret'] ].forEach(pair=>{
        pair[1] = pair[1] || pair[0]; tknz[ pair[0] ] = results[ pair[1] ];
      });
      break;
    case "2.0":
    case 2:
      [ ['access_token'], ['refresh_token'], ['token_type'] ].forEach(pair=>{
        pair[1] = pair[1] || pair[0]; tknz[ pair[0] ] = results[ pair[1] ];
      });
      break;
    }
    headers['Authorization'] = [ tknz.token_type || 'Bearer', tknz.access_token ].join(' ');
    callback( NULL, results );
    return results;
  });
  /*
   * var extraParams= {}; if( typeof oauth_verifier == "function" ) { callback=
   * oauth_verifier; } else { extraParams.oauth_verifier= oauth_verifier; }
   * this._performSecureRequest( oauth_token, oauth_token_secret, "POST",
   * this._accessUrl, extraParams, null, null, function(error, data, response) {
   * if( error ) callback(error); else { var results= querystring.parse( data );
   * callback(null, oauth_access_token, oauth_access_token_secret, results ); }
   * });
   */
};

Tokenizer.prototype.getRefreshedToken = function( callback ) {
  // console.log('getRefreshedToken');
  if( !isFunction(callback) ) { callback = Function(); }
  const tknz = this, request_type = 'refreshToken';
  const request_param = tknz[request_type], extra_param = { _nonceSize: 32 };
  // Callbacks are 1.0A related
  /*
   * if( this._authorize_callback ) extraParams["oauth_callback"]=
   * this._authorize_callback;
   */
  return tknz._performSecureRequest( request_param['method'] || 'POST', request_type, request_param, extra_param, function(er, data, response) {
    // same callback as getAccessToken;
    if(er) {
      return callback( er );
    }
    const results = data; // querystring.parse(data); => _performSecureRequest have executed parse
    // console.log('getAccessToken._performSecureRequest result:', er, data, results);
    const headers = tknz._headers = tknz._headers || { };
    switch(tknz.version) {
    case "1.0":
    case 1:
      [ ['access_token', 'oauth_token'], ['access_token_secret', 'oauth_token_secret'] ].forEach(pair=>{
        pair[1] = pair[1] || pair[0]; tknz[ pair[0] ] = results[ pair[1] ];
      });
      break;
    case "2.0":
    case 2:
      [ ['access_token'], ['refresh_token'], ['token_type'] ].forEach(pair=>{
        pair[1] = pair[1] || pair[0]; tknz[ pair[0] ] = results[ pair[1] ];
      });
      break;
    }
    headers['Authorization'] = [ tknz.token_type || 'Bearer', tknz.access_token ].join(' ');
    callback( NULL, results );
  });
  /*
   * var extraParams= {}; if( typeof oauth_verifier == "function" ) { callback=
   * oauth_verifier; } else { extraParams.oauth_verifier= oauth_verifier; }
   * this._performSecureRequest( oauth_token, oauth_token_secret, "POST",
   * this._accessUrl, extraParams, null, null, function(error, data, response) {
   * if( error ) callback(error); else { var results= querystring.parse( data );
   * callback(null, oauth_access_token, oauth_access_token_secret, results ); }
   * });
   */
};

Tokenizer.prototype.putRevokeToken = function( callback ) {
  // console.log('putRevokeToken');
  if( !isFunction(callback) ) { callback = Function(); }
  const tknz = this, request_type = 'revokeToken';
  const request_param = tknz[request_type], extra_param = { _nonceSize: 32 };
  // Callbacks are 1.0A related
  /*
   * if( this._authorize_callback ) extraParams["oauth_callback"]=
   * this._authorize_callback;
   */
  return tknz._performSecureRequest( request_param['method'] || 'POST', request_type, request_param, extra_param, function(er, data, response) {
    // same callback as getAccessToken;
    if(er) {
      return callback( er );
    }
    const results = data; // querystring.parse(data); => _performSecureRequest have executed parse
    // console.log('getAccessToken._performSecureRequest result:', er, data, results);
    const headers = tknz._headers = tknz._headers || { };
    delete headers['Authorization'];
    callback( NULL, results );
  });
};

Tokenizer.prototype.set = function( parameters ) {
  const tknz = this;
  return _mixin(tknz, parameters);
};

Tokenizer.prototype.apiCommon = function(url, options) {

  const tknz = this;
  options = options || { };
  options._extra = options._extra || { };
  if(options._extra._simpleArgs == NULL) { options._extra._simpleArgs = TRUE; } 
    // => avoid [azure AD] Request_BadRequest: Unrecognized query argument specified
  switch(tknz.version) {
  case "1.0":
  case 1:
    if(options['request_token'])
      tknz.request_token = options['request_token'];
    else if(!tknz.request_token)
      throw new Error("request_token is not set yet.");
    if(options['access_token_secret'])
      tknz.access_token_secret = options['access_token_secret'];
    else if(!tknz.access_token_secret)
      throw new Error("access_token_secret is not set yet.");
  case "2.0":
  case 2:
    if(options['access_token'])
      tknz.access_token = options['access_token'];
    else if(!tknz.access_token)
      throw new Error("access_token is not set yet.");
  default:
    new Error('Unknown version: ' + tknz.version);
  }
  options['_extra'] = _mixin({ _nonceSize:32 }, options['_extra']);
  return _mixin(/^https?:/.test(url) ? { url: url } : _mixin({ }, tknz.oauth.settings[ tknz.type ][ url ] || { }), options);

};

Tokenizer.prototype.del = function(url, options, callback) {
  const tknz = this;
  if(isFunction(options)) callback = options, options = { };
  options = tknz.apiCommon(url, options);
  return tknz._performSecureRequest( options.method || "DEL", "api",
    options, options._extra, NULL, NULL, callback );
};

Tokenizer.prototype.get = function(url, options, callback) {
  const tknz = this;
  if(isFunction(options)) callback = options, options = { };
  options = tknz.apiCommon(url, options);
  return tknz._performSecureRequest( options.method || "GET", "api",
    options, options._extra, NULL, NULL, callback );
};

Tokenizer.prototype._putOrPost= function(method, url, options, callback) {
  const tknz = this;
  if(isFunction(options)) {
    callback = options, options = { };
  }
  options = tknz.apiCommon(url, options);
  let post_body = options['post_body'], post_content_type = options['post_content_type'];
  if( !post_content_type ) 
    post_content_type = NULL;
  return tknz._performSecureRequest( options.method || method, "api", 
    options, options._extra, post_body, post_content_type, callback );
};
Tokenizer.prototype.put= function(url, options, callback) {
  const tknz = this;
  return tknz._putOrPost("PUT", url, options, callback);
};
Tokenizer.prototype.post= function(url, options, callback) {
  const tknz = this;
  return tknz._putOrPost("POST", url, options, callback);
};

// ============== Both prototype ============== //
Authorizer.prototype._getSignature = 
  Tokenizer.prototype._getSignature = 
    function(method, url, parameters, tokenSecret) {
  var signatureBase = _createSignatureBase( method, url, parameters );
  // encodedSecret is already encoded in getRequestToken() .
  var hash= "", key= this.encodedSecret + "&" + (_encodeData(tokenSecret) || "");
  if( this.options.signatureMethod == "PLAINTEXT" ) 
    hash= _encodeData(key);
  else {
     if( crypto.Hmac ) 
       hash = crypto.createHmac("sha1", key).update(signatureBase).digest("base64");
     else 
       hash= sha1.HMACSHA1(key, signatureBase);  
  }
  return hash;
};

// subroutined prototype methods
Authorizer.prototype._performSecureRequest = 
  Tokenizer.prototype._performSecureRequest = 
    function( method, request_type, request_param, extra_param, post_body, post_content_type,  callback ) {
  
  const izer = this;
  method = (request_param.method || method).toUpperCase();
  const orderedParameters = izer._prepareParameters(method, request_param, extra_param);
  outDebug('_performSecureRequest', [ method, request_type, request_param, extra_param, orderedParameters ]);
  
  // args
  // support with callback at post_body
  if( isFunction(post_body) ) {
    callback = post_body;
    post_body = "";
  }
  if( !isFunction(callback) ) {
    callback = Function();
  }
  if( !post_content_type ) 
    post_content_type = "application/x-www-form-urlencoded";

  // parsedUrl port set
  const parsedUrl= URL.parse( request_param.url, false );
  if( parsedUrl.protocol == "http:" && !parsedUrl.port ) 
    parsedUrl.port= 80;
  if( parsedUrl.protocol == "https:" && !parsedUrl.port ) 
    parsedUrl.port= 443;

  const headers= {
    "Accept" : "*/*",
    "Connection" : "close",
    "User-Agent" : "Node OAuth authentication"
  };
  const authorization 
    = izer._buildAuthorizationHeaders(orderedParameters);

  if ( /authorize/.test( request_type ) ) { // OAuth Echo header require.
    headers["X-Verify-Credentials-Authorization"] = authorization;
  } else {
    headers["Authorization"] = authorization;
  }

  headers["Host"] = parsedUrl.host;
  if(izer.origin != NULL) {
    // for azureAD requirements. if missing Origin, 
    // AADSTS9002327: Tokens issued for the 'Single-Page Application' client-type may only be redeemed via cross-origin requests.
    // occurs in getAccessToken.
    headers["Origin"] = izer.origin; 
  }

  // Fixed header will given from header e.g.) access_token
  for(let key in izer._headers ) {
    if (izer._headers.hasOwnProperty(key)) 
      headers[key]= izer._headers[key];
  }

  // Filter out any passed extra_param that are really to do with OAuth
  for(let key in extra_param) {
    if( izer._hasOAuthPrefix( key )) 
      delete extra_param[key];
  }

  let path;
  if( !parsedUrl.pathname  || parsedUrl.pathname == "" ) {
    parsedUrl.pathname = "/";
  }
  if( parsedUrl.query ) {
    path = [ parsedUrl.pathname, parsedUrl.query ].join("?");
  } else if( method == "GET" ) {
    path = _makeUrl(parsedUrl.pathname, orderedParameters, isArray(orderedParameters));
  } else {
    path = parsedUrl.pathname;
  }
  outDebug('parsedUrl', [ 'Path made?', method, path, 'parsedUrl?', parsedUrl ]);
  return new Promise((rsl, rej)=>{
    
    // redirect if response is given
    if( method == "GET" && izer.options['response']) {
      try {
        callback();
        rsl(izer.options['response'].redirect( _makeUrl(request_param.url, orderedParameters) ));
       } catch(e) {
        callback(e);
        rej(e);
      }
      return; // <-- END_OF_PROCESS <--
    }
  
    // substitute post_body automatically
    if( (method == "POST" || method =="PUT") && !post_body ) {
      post_body = { };
      orderedParameters.forEach(pair=>post_body[ pair[0] ] = pair[1]);
      switch(post_content_type) {
  
      case "application/json":
        post_body = JSON.stringify(post_body);
        break;
      case "application/x-www-form-urlencoded":
      default:
        post_body = querystring.stringify(post_body);
  
      }
    }
  
    headers["Content-length"] = Buffer.byteLength(post_body || "");
    headers["Content-Type"] = post_content_type;
    outDebug('_performSecureRequest', [ 'request?', method, path, headers, post_body ]);
  
    // ajax request start .
    const request = parsedUrl.protocol == "https:" ?
      _createClient(parsedUrl.port, parsedUrl.hostname, method, path, headers, TRUE):
      _createClient(parsedUrl.port, parsedUrl.hostname, method, path, headers);
  
    if( (method == "POST" || method =="PUT") && post_body ) { 
      request.write(post_body);
    }
    // #### get Request Token ####
    // oauth_consumer_key="",oauth_nonce="",oauth_signature_method="",oauth_timestamp="",oauth_version="",oauth_signature=""
    // key = encodedConsumerSecret ( no tkn_scr )
    // #### getAccessToken ####
    // oauth_consumer_key="",oauth_nonce="",oauth_signature_method="",oauth_timestamp="",oauth_token="",oauth_verifier="",oauth_version="",oauth_signature=""
    // key = encodedConsumerSecret + request_token_scr
    // #### access api ####
    // oauth_consumer_key="",oauth_nonce="",oauth_signature_method="",oauth_timestamp="",oauth_token="",oauth_version="",oauth_signature=""
    // key = encodedConsumerSecret + access_token_scr
    request.on('response', res=>{
      try {
        accept(res, rsl, rej);
      } catch(e) {
        rej(e);
      }
    }).on("error", e=>{
      try {
        callback(e) && rej(e);
      } catch(e) {
        rej(e);
      }
    }).end();
    
  });

  function accept(response, resolve, reject) {
    let data = "";
    response.setEncoding('utf8');
    response.on('data', chunk=>data += chunk);
    response.on('end', ()=>{
      // TODO api response can choice "JSON.parse()" or "PLAIN TEXT"
      outDebug('_performSecureRequest', [ 'response?', response.statusCode, data ]);
      const modifier = request_param['modifier'];
      if ( response.statusCode >= 200 && response.statusCode <= 299 ) {
        try {
          data = !is('string', data) ? data: JSON.parse(data);
        } catch(e) {
          /*IGNORE*/
        };
        try {
          data = !is('string', data) ? data: querystring.parse(data);
        } catch(e) {
          /*IGNORE*/
        };
        if(isFunction(modifier)) { data = modifier(data); }
        callback(NULL, data, response);
        resolve(data);
        return;
      }
      // Follow 302 redirects with Location HTTP header
      if(response.statusCode == 302 && response.headers && response.headers.location) {
        _mixin(request_param, { url: response.headers.location });
        izer._performSecureRequest( method, request_param , extra_param, post_body, post_content_type,  callback)
          .then(resolve)['catch'](reject);
        return;
      }
      const e = new Error(['OAuth performing failed. ( request_type = "', request_type, '" )'].join(""));
      outLog('Error request to: ' + [ method, path ].join(' '));
      console.log('headers?', headers);
      console.log('orderedParameters?', orderedParameters);
      console.log('response? statusCode: ' + response.statusCode, data);
      callback(e, data, response);
      reject(e);
    });
  }

};

// Is the parameter considered an OAuth parameter
Authorizer.prototype._hasOAuthPrefix = 
  Tokenizer.prototype._hasOAuthPrefix = 
    function(parameter) {
  var prefix = this['arg_prefix'];
  if(typeof prefix == "undefined")
    return true;
  var m = parameter.match(new RegExp(['^',prefix].join("")));
  return m && ( m[0] == prefix);
};

Authorizer.prototype._prepareParameters = 
  Tokenizer.prototype._prepareParameters = 
    function(method, request_param, extra_param ) {

  const izer = this;
  const parsedUrl = URL.parse(request_param.url, false);
  const oauthParameters= { };
  const encodeURIs = new Set(request_param.enc || [ ]);
  let sig = ""; 
  
  // set setting.arg values.
  // arg: <Array>.( <String>key = send_name | { <String>key: <String>send_name } )
  for(let i in request_param.arg) {

    const val = request_param.arg[i];
    const mrk = ( request_param.mrk || [ ] )[i] || (method == 'GET' ? '+': ',');
    let key, send_name;
    if(typeof val == "object"){
      key = Object.keys(val)[0];
      send_name = val[key];
    } else {
      key = val;
      send_name = val;
    }

    if(!izer._hasOAuthPrefix(send_name)) {
      send_name = [ izer.arg_prefix, send_name ].join("");
    }
    // console.log('prepare arg[' + i + ']', key, send_name, izer[ key ]);

    if(izer[ key ] != NULL) {
      // TODO check : need _normalizeUrl() ?
      // console.log('izer[' + key + ']?', izer[ key ], '=> ' + send_name);
      if(isArray( izer[ key ] )) {
        oauthParameters[ send_name ]
          = izer[ key ].map(v=>encodeURIs.has( key ) ? encodeURIComponent(v): v).join(mrk);
      } else {
        oauthParameters[ send_name ] 
          = encodeURIs.has( key ) ? encodeURIComponent(izer[ key ]): izer[ key ];
      }
    }

  }

  if( extra_param ) {
    for(let i in extra_param) 
      if(!/^_/.test(i)) oauthParameters[i]= extra_param[i];
  }
  
  if( extra_param['_simpleArgs'] ) {
    return oauthParameters;
  }
  
  _mixin(oauthParameters,   {
    "oauth_timestamp": _getTimestamp(),
    "oauth_nonce": _getNonce(extra_param._nonceSize),
    "oauth_version": izer.version,
    "oauth_signature_method":  izer.options.signatureMethod
  });
  
  const tkn_scr = request_param.key ? izer[request_param.key]: NULL;
  // TODO check
  if( parsedUrl.query ) {
    var extraParameters= querystring.parse(parsedUrl.query);
    for(var key in extraParameters ) {
      var value= extraParameters[key];
      if( typeof value == "object" ){
        // TODO: This probably should be recursive
        for(var key2 in value)
          oauthParameters[key + "[" + key2 + "]"] = value[key2];
      } else 
        oauthParameters[key]= value;
    }
  }
  
  const orderedParameters= _sortRequestParams( _makeArrayOfArgumentsHash(oauthParameters) );
  if(izer.version == "1.0" || izer.version == 1) {
    izer.encodedSecret = _encodeData( izer['consumer_secret'] );
    sig = izer._getSignature( method,  request_param.url,  _normaliseRequestParams(oauthParameters), tkn_scr );
    orderedParameters[orderedParameters.length]= ["oauth_signature", method == "GET"?_encodeData(sig):sig];
  }
  return orderedParameters;

};

// build the OAuth request authorization header
Authorizer.prototype._buildAuthorizationHeaders = 
  Tokenizer.prototype._buildAuthorizationHeaders = 
    function(orderedParameters) {
      
  const izer = this;
  let authHeader = "OAuth ";
  
  // TODO check
  /*
   * if( this._isEcho ) { authHeader += 'realm="' + this._realm + '",'; }
   */
  for(let i= 0 ; i < orderedParameters.length; i++) {
    // Whilst the all the parameters should be included within the signature,
    // only the oauth_ arguments
    // should appear within the authorization header.
    // if( this._hasOAuthPrefix(orderedParameters[i][0]) )
    authHeader += [ _encodeData(orderedParameters[i][0]), "=\"",  _encodeData(orderedParameters[i][1]), "\"," ].join('');
  }
  return authHeader.substring(0, authHeader.length-1);

};

/** TODO not need ?  >> **/
/*
 * OAuth.prototype.signUrl= function(url, oauth_token, oauth_token_secret,
 * method) { if( method === undefined ) method= "GET"; var orderedParameters=
 * this._prepareParameters(request_param, extra_param); var parsedUrl=
 * URL.parse( url, false ); var query=""; for( var i= 0 ; i <
 * orderedParameters.length; i++) { query+= orderedParameters[i][0]+"="+
 * _encodeData(orderedParameters[i][1]) + "&"; } query= query.substring(0,
 * query.length-1); return parsedUrl.protocol + "//"+ parsedUrl.host +
 * parsedUrl.pathname + "?" + query; };
 */
/** << **/

// generic functions

// arguments change to array
function _arg2arr(args) {
  return isFunction(Array.from) ? Array.from(args): Array.prototype.slice.call(args);
}

// extend object
function _mixin(target, source) {
  if(isFunction(Object.assign)) {
    return Object.assign(target, source);
  }
  for( var key in source)
    if(source.hasOwnProperty(key))
      target[key] = source[key];
  return target;
}

// chain asynchronous functions
function _chain(actors, self, args) {
  if(!self) {
    self = this;
  }
  next.apply(self, [ NULL ].concat(typeof args == "undefined"? [ ]: args));
  function next(er0) {
    let actor = NULL, args;
    try {
    
      if(er0)
        return actors.pop().call(self, er0); // => error will gives to the last actor
       
      actor = actors.shift();
      if(!isFunction( actor ))
        throw new Error('Unexpected chain member.');
        
      // arguments will inherits to the next actor with next function.
      args = Array.prototype.slice.call(arguments);
      if(actors.length > 0) {
        args = args.slice(1).concat(next);
      }
      process.nextTick(()=>actor.apply(self, args));
     
    } catch(e) {
      if(actors.length === 0) {
        if(e != NULL)
          return actor.call(self, e);  // => error will gives to the last actor
        else
          throw e; // UNEXPECTED NULL THROWN
      }
      next(e); // => error will gives to the last actor
    }
  }
}

var NONCE_CHARS= ['a','b','c','d','e','f','g','h','i','j','k','l','m','n',
                  'o','p','q','r','s','t','u','v','w','x','y','z','A','B',
                  'C','D','E','F','G','H','I','J','K','L','M','N','O','P',
                  'Q','R','S','T','U','V','W','X','Y','Z','0','1','2','3',
                  '4','5','6','7','8','9'];
function _getNonce(nonceSize) {
   var result = [];
   var chars= NONCE_CHARS;
   var char_pos;
   var nonce_chars_length= chars.length;
   for (var i = 0; i < nonceSize; i++) {
       char_pos= Math.floor(Math.random() * nonce_chars_length);
       result[i]=  chars[char_pos];
   }
   return result.join('');
}
function _getTimestamp() {
  return Math.floor( (new Date()).getTime() / 1000 );
}
function _encodeData(toEncode){
 if( toEncode == null || toEncode == "" ) 
   return "";
 else {
    var result= encodeURIComponent(toEncode);
    // Fix the mismatch between OAuth's RFC3986's and Javascript's beliefs in
    // what is right and wrong ;)
    return result.replace(/\!/g, "%21")
                 .replace(/\'/g, "%27")
                 .replace(/\(/g, "%28")
                 .replace(/\)/g, "%29")
                 .replace(/\*/g, "%2A");
 }
}
function _decodeData(toDecode) {
  if( toDecode != null ) {
    toDecode = toDecode.replace(/\+/g, " ");
  }
  return decodeURIComponent( toDecode);
}
function _normaliseRequestParams(arguments) {
  var argument_pairs= _makeArrayOfArgumentsHash(arguments);
  // First encode them #3.4.1.3.2 .1
  for(var i=0;i<argument_pairs.length;i++) {
    argument_pairs[i][0]= _encodeData( argument_pairs[i][0] );
    argument_pairs[i][1]= _encodeData( argument_pairs[i][1] );
  }
  
  // Then sort them #3.4.1.3.2 .2
  argument_pairs= _sortRequestParams( argument_pairs );
  
  // Then concatenate together #3.4.1.3.2 .3 & .4
  var args= "";
  for(var i=0;i<argument_pairs.length;i++) {
      args+= argument_pairs[i][0];
      args+= "=";
      args+= argument_pairs[i][1];
      if( i < argument_pairs.length-1 ) args+= "&";
  }     
  return args;
}

function _createSignatureBase(method, url, parameters) {
  url= _encodeData( _normalizeUrl(url) ); 
  parameters= _encodeData( parameters );
  return method.toUpperCase() + "&" + url + "&" + parameters;
}
// Sorts the encoded key value pairs by encoded name, then encoded value
function _sortRequestParams(argument_pairs) {
  // Sort by name, then value.
  argument_pairs.sort(function(a,b) {
      if ( a[0]== b[0] )  {
        return a[1] < b[1] ? -1 : 1; 
      }
      else return a[0] < b[0] ? -1 : 1;  
  });

  return argument_pairs;
}
// Takes an object literal that represents the arguments, and returns an array
// of argument/value pairs.
function _makeArrayOfArgumentsHash(argumentsHash) {
  var argument_pairs= [];
  for(var key in argumentsHash ) {
      var value= argumentsHash[key];
      if( Array.isArray(value) ) 
        for(var i=0;i<value.length;i++) 
          argument_pairs.push([key, value[i]]);
      else 
        argument_pairs.push([key, value]);
  }
  return argument_pairs;  
} 
function _createClient( port, hostname, method, path, headers, sslEnabled ) {
  outDebug('_createClient', arguments);
  var options = {
    host: hostname,
    port: port,
    path: path,
    method: method,
    headers: headers
  };
  var httpModel;
  if( sslEnabled ) {
    httpModel= https;
  } else {
    httpModel= http;
  }
  return httpModel.request(options);     
};
function _normalizeUrl(url) {
  outDebug('_normalizeUrl', arguments);
  var parsedUrl= URL.parse(url, true);
   var port ="";
   if( parsedUrl.port ) { 
     if( (parsedUrl.protocol == "http:" && parsedUrl.port != "80" ) ||
         (parsedUrl.protocol == "https:" && parsedUrl.port != "443") ) {
           port= ":" + parsedUrl.port;
         }
   }

  if( !parsedUrl.pathname  || parsedUrl.pathname == "" ) 
    parsedUrl.pathname ="/";
   
  return parsedUrl.protocol + "//" + parsedUrl.hostname + port + parsedUrl.pathname;
}
function _makeUrl(url, headers, array) {
  outDebug('_makeUrl', arguments);
  let mrk = url.indexOf("?") == -1 ? "?": "&";
  if(array) {
    // orderedParameters pattern
    for(let i = 0; i < headers.length; i++) {
      url = [ url, mrk, headers[i][0],"=",headers[i][1] ].join("");
      mrk = "&";
    }
  } else {
    for(let i in headers) {
      url = [ url, mrk, i, "=", headers[i] ].join("");
      mrk = "&";
    }
  }
  return url;
}


// -----
function outLog() {
  console.log.apply(console, _getLogArgs(arguments));
}
function outDebug(ty, args) {
  if(!isArray(OAuth.debug) || OAuth.debug.indexOf(ty) == -1) { return; }
  console.log.apply(console, _getLogArgs(args, ty));
}
function _getLogArgs(a, mark) {
  const args = Array.from(a);
  args.unshift(new Date().toGMTString() + ' - [oauth/oauth.js]' + (mark ? ' ' + mark + ':': ''));
  return args;
}

// -----
function is(ty, x) {
  return typeof x == ty;
}
function isFunction(x) {
  return typeof x == 'function';
}
function isArray(x) {
  return Array.isArray(x);
}