var net = require('net'),
    tls = require('tls'),
    http = require('http'),
    https = require('https'),
    httpProxy = require('http-proxy'),
    stream = require('stream'),
    fs = require('fs'),
    crypto = require('crypto'),
    socks = require('./socks.js'),
    xmljs = require('xml2js'),
    dns = require('dns'),
    XMLSplitter = require('xml-splitter'),
    util = require('util');

require('buffer').INSPECT_MAX_BYTES = 1024;

var xmlBuilder = new xmljs.Builder({headless:true});

var din = fs.createWriteStream('data_in.log');
var dout = fs.createWriteStream('data_out.log');

var proxies = {};

function makeNullProxy(port, address, callback) {
  callback(port, address);
}

function makeProxy(port, address, callback, createServer) {
  var key = address + ':' + port;

  // Check if we already have a proxy for this server
  var proxySrv = proxies[key];
  if (proxySrv) {
    return proxySrv.addressWait(callback);
  }

  var server = createServer();

  var addrWaiters = [callback];
  var doAddressCb = function(callback) {
    var proxyAddr = server.address();
    return callback(proxyAddr.port, 'localhost');
  };
  server.addressWait = function(callback) {
    if (addrWaiters) {
      addrWaiters.push(callback);
    } else {
      doAddressCb(callback);
    }
  };
  server.listen(0, function() {
    for (var i = 0; i < addrWaiters.length; ++i) {
      doAddressCb(addrWaiters[i]);
    }
    addrWaiters = null;
  });

  proxies[key] = server;
}

function makeXmlSplitter() {
  var dout = new stream.PassThrough();
  var din = new stream.PassThrough();

  var STARTMARK = '<SNTL>';
  var ENDMARK = '</SNTL>';

  var buf = '';
  din.on('data', function(d) {
    buf += d.toString();

    while(true) {
      if (buf.length < STARTMARK.length) {
        return;
      }

      var start = buf.indexOf(STARTMARK);
      if (start !== 0) {
        throw new Error('Expected SNTL');
      }

      var end = buf.indexOf(ENDMARK);
      if (end === -1) {
        // Not enough data yet
        return;
      }

      var msgStr = buf.substr(STARTMARK.length, end - STARTMARK.length);
      var msg = xmljs.parseString(STARTMARK + msgStr + ENDMARK, function(err, data) {
        if (err) {
          console.log('XML Message Parse Error', err);
          return;
        }

        dout.emit('data', data);
      });

      buf = buf.substr(end + ENDMARK.length);
    }
  });

  dout.stream = din;
  return dout;
}

var FLASHPOLICY = "<cross-domain-policy><allow-access-from domain=\"*\" to-ports=\"*\"/></cross-domain-policy>\0";
function makeGameProxy(port, address, secure, callback) {
  if (!secure) {
    throw new Error('We only support SSL game server connections at the moment!');
  }

  return makeProxy(port, address, callback, function() {

    var wmsSrv = net.createServer();

    wmsSrv.on('connection', function(socket) {
      console.log('new connection!');

      var gameType = 'UNKNOWN';
      var inFile = null;
      var outFile = null;
    
      var socketXml = makeXmlSplitter();
      var proxyXml = makeXmlSplitter();

      socketXml.on('data', function(msg) {
        console.log('SOCKET MSG:', util.inspect(msg,{depth:10}));
        
        if (msg.SNTL.HDR[0].TYPE[0] === 'AUTHENTICATE') {
          gameType = msg.SNTL.DATA[0].AUTH[0].launchGame[0];
          
          inFile = fs.createWriteStream('logs/' + gameType + '_in.log');
          outFile = fs.createWriteStream('logs/' + gameType + '_out.log');
        }
        
        if (outFile) outFile.write(JSON.stringify(msg, null, '  '));
      });

      proxyXml.on('data', function(msg) {
        console.log('PROXY MSG:', util.inspect(msg,{depth:10}));

        if (msg.SNTL.HDR[0].TYPE[0] === 'INITIALIZE_SLOT') {
          var initData = xmlBuilder.buildObject(msg.SNTL.DATA[0]);
          fs.writeFileSync('configs/' + gameType + '.xml', initData);
        }
        
        if (inFile) inFile.write(JSON.stringify(msg, null, '  '));
      });

      var proxy = tls.connect(port, address, {rejectUnauthorized:false}, function() {
        console.log('Socket Connected!');
      });

      proxy.on('data', function(d) {
        //console.log('Proxy Data |' + d.toString() + '|');
        proxyXml.stream.write(d);
        socket.write(d);
      });
      socket.on('data', function(d) {
        if (d.toString() === "<policy-file-request/>\0") {
          console.log('Policy Request');
          socket.write(FLASHPOLICY);
          return;
        }
        //console.log('Socket Data |' + d.toString() + '|');
        socketXml.stream.write(d);
        proxy.write(d);
      });
      proxy.on('error', function() {
        // Ignored...
      });
      socket.on('error', function() {
        // Ignored...
      });
      proxy.on('close', function() {
        socket.end();
      });
      socket.on('close', function() {
        proxy.end();
      });
    });

    return wmsSrv;

  });
}

function makeHttpsProxy(port, address, credshost, hostname, reqCb, callback) {
  return makeProxy(port, address, callback, function() {
    var proxyTgt = 'https://' + hostname + ':' + port;

    var proxy = httpProxy.createProxyServer({
      secure: false,
      target: proxyTgt
    });

    var server = https.createServer({
      key: fs.readFileSync('creds/' + credshost + '.pem'),
      cert: fs.readFileSync('creds/' + credshost + '.crt')
    });

    server.on('request', function(req, res) {
      req.intercept = function(resCb) {
        var _writeHead = res.writeHead.bind(res);
        var _write = res.write.bind(res);
        var _end = res.end.bind(res);
        var status = 0;
        var sendbufs = [];
        res.writeHead = function(statusCode, reason, headers) {
          if (reason !== undefined || headers !== undefined) {
            throw new Error('Uhh ohhhh....');
          }
          status = statusCode;
        };
        res.write = function(d) {
          sendbufs.push(d);
          return true;
        };
        res.end = function(d) {
          if (d) {
            sendbufs.push(d);
          }
          var df = null;
          if (sendbufs.length > 0) {
            df = Buffer.concat(sendbufs);
          }
          resCb(df, status, _writeHead, _write, _end);
          return true;
        };
      };

      reqCb(req, res, function() {
        proxy.web(req, res);
      });
    });

    return server;
  });
}

// WMS Game Server stuff


var server = socks.createServer(function (socket, port, address, proxy_ready)
{
  var makeMyProxy = null;

  if (address == '5.62.86.7' && port == 443) {
    var handler = function(req, res, next) {
      console.log('Forwarding ' + req.url);

      var propsUrl = '/ClientProperties/FrameworkStubProperties.svc/properties';
      if (req.url.substr(0, propsUrl.length) === propsUrl) {
        // This is a framework request.
        var paramsS = req.url.substr(propsUrl.length+1);
        var params = paramsS.split('/');
        var gameName = params[3];

        req.intercept(function(d, statusCode, writeHead, write, end) {
          console.log('INTERCEPTING PROPERTIES : ' + gameName);

          xmljs.parseString(d, {'trim': true}, function(err, xml) {
            function failPassthru() {
              writeHead(statusCode);
              write(d);
              end();
            }

            if (err) {
              console.log('Failed to parse properties data...');
              return failPassthru();
            }

            // Some checks for sanity
            var gameSrv = xml.properties.gameServerConnection;
            var gsvHost = gameSrv[0].host[0];
            var gsvPort = parseInt(gameSrv[0].port[0]);
            var gsvSsl = gameSrv[0].secure[0] == 'true';
            if (gsvHost.indexOf('.mlt.casinarena.com') === -1 ||
              gsvPort !== 8499 ||
              gsvSsl !== true) {
              console.log('Game server data was unexpected!', gameSrv);
              return failPassthru();
            }

            makeGameProxy(gsvPort, gsvHost, gsvSsl, function(pport) {
              // Update game server location
              gameSrv[0].host[0] = '127.0.0.1';
              gameSrv[0].port[0] = pport;
              gameSrv[0].secure[0] = 'false';
              gameSrv[0].policyFile[0] = 'xmlsocket://127.0.0.1:' + pport;

              // Disable any analytics adapters
              delete xml.properties.analytics;

              // Logging TO THE MAX
              xml.properties.logging[0].logLevel[0] = 0xFFFFFFFF.toString();

              var newd = new Buffer(xmlBuilder.buildObject(xml));
              res.setHeader('Content-Length', newd.length);
              writeHead(200);
              write(newd);
              end();
            });
          });
        });

        next();
      } else {
        next();
      }
    };
    makeMyProxy = makeHttpsProxy.bind(this, port, address, '.mlt.casinarena.com', 'gweb.mlt.casinarena.com', handler);
  } else if (address == '107.170.199.119' && port == 443) {
    var handler = function(req, res, next) {
      console.log('GOT HTTPS REQUEST', req.headers);

      // disable gzip, because ick...
      delete req.headers['accept-encoding'];

      req.intercept(function(d, write, end) {
        //console.log('WRITETHRU', d.toString());

        write(d);
        end();
      });

      next();
    };
    makeMyProxy = makeHttpsProxy.bind(this, port, address, 'gotofail.com', 'gotofail.com', handler);
  } else {
    makeMyProxy = makeNullProxy.bind(this, port, address);
  }

  makeMyProxy(function(pport, paddress) {
    console.log('Proxying ' + address + ':' + port + ' to ' + paddress + ':' + pport);

    var proxy = net.connect(pport, paddress, proxy_ready);
    proxy.on('data', function(d) {
      try {
        socket.write(d);
      } catch(e) {
      }
    });
    socket.on('data', function(d) {
      try {
        proxy.write(d);
      } catch(e) {
      }
    });
    proxy.on('error', function() {
      // Ignored...
    });
    socket.on('error', function() {
      // Ignored...
    });
    proxy.on('close', function() {
      socket.end();
    });
    socket.on('close', function() {
      proxy.end();
    });
  });
});

server.on('error', function (e) {
  console.error('SERVER ERROR: %j', e);
});
server.listen(8888);
console.log("Listening on port 8888!");
