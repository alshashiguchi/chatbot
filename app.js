'use strict';

const 
  bodyParser = require('body-parser'),
  config = require('config'),
  crypto = require('crypto'),
  express = require('express'),
  https = require('https');

var app = express();

app.set('port', process.env.PORT || 5000);
app.use(bodyParser.json({ verify: verifyRequestSignature }));
app.use(express.static('public'));

const APP_SECRET = (process.env.MESSENGER_APP_SECRET) ? 
  process.env.MESSENGER_APP_SECRET :
  config.get('appSecret');

const VALIDATION_TOKEN = (process.env.MESSENGER_VALIDATION_TOKEN) ?
  (process.env.MESSENGER_VALIDATION_TOKEN) :
  config.get('validationToken');

const PAGE_ACCESS_TOKEN = (process.env.MESSENGER_PAGE_ACCESS_TOKEN) ?
  (process.env.MESSENGER_PAGE_ACCESS_TOKEN) :
  config.get('pageAccessToken');

const SERVER_URL = (process.env.SERVER_URL) ?
  (process.env.SERVER_URL) :
  config.get('serverURL');

if (!(APP_SECRET && VALIDATION_TOKEN && PAGE_ACCESS_TOKEN && SERVER_URL)) {
  console.error("Configurações não informadas");
  process.exit(1);
}

app.get('/webhook', function(req, res) {
  if (req.query['hub.mode'] === 'subscribe' &&
      req.query['hub.verify_token'] === VALIDATION_TOKEN) {
   
    console.log("Validando webhook");

    res.status(200).send(req.query['hub.challenge']);

  } else {
    console.error("Falha na validação. Verifique o token e tente novamente");
    res.sendStatus(403);          
  }  
});

app.get('/status', function(req, res) {
    res.writeHead(200, {"Content-Type": "text/plain"});
    res.end("Status: OK");
});

function verifyRequestSignature(req, res, buf) {
  
  var signature = req.headers["x-hub-signature"];

  if (!signature) {
    console.error("Não foi possível validar a assinatura da requisição");
  } else {
    var elements = signature.split('=');
    var method = elements[0];
    var signatureHash = elements[1];

    var expectedHash = crypto.createHmac('sha1', APP_SECRET)
                        .update(buf)
                        .digest('hex');

    if (signatureHash != expectedHash) {
      throw new Error("Não foi possível validar a assinatura da requisição");
    }
  }
}

app.listen(app.get('port'), function() {
  console.log('ChatBot está em execução na porta ', app.get('port'));
});

module.exports = app;