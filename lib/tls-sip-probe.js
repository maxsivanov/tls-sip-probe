var tls = require('tls');
var crypto = require('crypto');

function md5(data) {
    return crypto.createHash('md5').update(data).digest("hex");
}

var results = {
    OK: "OK",
    FORBIDDEN: "FORBIDDEN",
};

var states = {
    INIT: "",
    NO_AUTH: "unauthorized",
    AUTHED: "authotized",
    FORBIDDEN: "forbidden",
};

var proto = "sip";
var callid = md5((new Date()).toGMTString());

function authHeader(method, uri, user, password, realm, nonce) {
    var x = md5(md5(user+":"+realm+":"+password)+":"+nonce+":"+md5(method+":"+uri));
    return 'Digest username="'+user+'", realm="'+realm+'", nonce="'+nonce+'", uri="'+uri+'", response="'+x+'", algorithm=MD5';
}

function sendSIPMessage(socket, method, seq, host, user, add) {
    add = add || [];
    var my_addr = socket.address(); 
    var msg = method+" "+proto+"s:"+host+" SIP/2.0\r\n" +
        "Via: SIP/2.0/TLS "+my_addr.address+":"+my_addr.port+";branch=z9hG4bKnashds7\r\n" +
        "Max-Forwards: 70\r\n" +
        "From: User <"+proto+":"+user+"@"+host+">;tag=a73kszlfl\r\n" +
        "To: User <"+proto+":"+user+"@"+host+">\r\n" +
        "Call-ID: "+callid+"\r\n" +
        "CSeq: "+(seq++)+" "+method+"\r\n" +
        "Contact: <"+proto+":"+user+"@"+my_addr.address+":"+my_addr.port+">\r\n" +
        add.join("\r\n") + (add.length?"\r\n":"") +
        "Content-Length: 0\r\n\r\n";
    if (!socket.write(msg)) {
         socket.once('drain', undefined);
    }
}

function connect(host, port, user, pass, cb) {
    
    port = port || 5061;

    var socket = tls.connect({
        host: host,
        port: port,
        rejectUnauthorized: false
    }, function(err, data) {

        if (err) {
            cb(err);
        }

        var seq = 1;
        var state;
        var retry;

        var attempt = function () {
            return (retry--);
        };

        var no_attemps = function () {
            return !retry;
        };

        var change = function (name) {
            state = name;
            retry = 2;
        };

        var get = function () {
            return state;
        };

        change(states.INIT);

        sendSIPMessage(socket, "REGISTER", seq, host, user);
        
        socket.on('data', function (data) {
            var msg = data.toString().split(/\n/);
            var toState = {};
            msg.forEach(function (line) {
                if (line.toLowerCase().indexOf('www-authenticate') === 0) {
                    var rNonce = /nonce="([0-9a-f]+)"/.exec(line);
                    var rRealm = /realm="([0-9a-z_\.-]+)"/.exec(line);
                    if (rNonce && rRealm) {
                        toState = {
                            state: states.NO_AUTH,
                            data: authHeader("REGISTER", proto+"s:"+host, user, pass, rRealm[1], rNonce[1]),
                        };
                    }
                }
                if ((get() === states.NO_AUTH) && (line.toLowerCase().indexOf('sip/2.0 200') === 0)) {
                    toState = {
                        state: states.AUTHED,
                    };
                }
                if ((get() === states.NO_AUTH) && (line.toLowerCase().indexOf('sip/2.0 403') === 0)) {
                    toState = {
                        state: states.FORBIDDEN,
                    };
                }
            }); 
            if ((toState.state === states.NO_AUTH) && attempt()) {
                sendSIPMessage(socket, "REGISTER", seq, host, user, [ "Authorization: " + toState.data ]);
            }
            change(toState.state);
            if (no_attemps()) {
                cb(new Error("No attempts left"));
            }
            if (get() === states.AUTHED) {
                cb(null, results.OK);
            }
            if (get() === states.FORBIDDEN) {
                cb(null, results.FORBIDDEN);
            }
        });

    });

    socket.on('error', function (data) {
        cb(data);
    });
}

module.exports = {
    connect: connect,
    results: results,
};
