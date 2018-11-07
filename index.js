const jws = require('jws');
const x509 = require('x509');
const NodeRSA = require('node-rsa');

const _x5c_to_cert = (x5c) => {
  var cert, y;
  cert = ((function () {
    var _i, _ref, _results;
    _results = [];
    for (y = _i = 0, _ref = x5c.length; _i <= _ref; y = _i += 64) {
      _results.push(x5c.slice(y, +(y + 63) + 1 || 9e9));
    }
    return _results;
  })()).join('\n');
  return ("-----BEGIN CERTIFICATE-----\n" + cert + "\n-----END CERTIFICATE-----");
}

const validarSimple = (jwsSigned) => {
  const parsedKey = recuperarCertificados(jwsSigned)[0];
  const key = new NodeRSA();
  key.importKey({
    n: new Buffer(parsedKey.publicKey.n, 'hex'),
    e: parseInt(parsedKey.publicKey.e, 10)
  }, 'components-public');
  const exportedKey = key.exportKey('public');
  return jws.verify(jwsSigned, 'RS256', exportedKey);
}
const recuperarCertificados = (jwsSigned) => {
  const jwsDecoded = jws.decode(jwsSigned);
  const certificados = jwsDecoded.header.x5c;
  return certificados.map(x => {
    return x509.parseCert(_x5c_to_cert(x));
  });

}
const recuperarCertificadosSubject = (jwsSigned) => {
  return recuperarCertificados(jwsSigned).map(x => x.subject);
}

const toJson = (jwsSigned) => {
  return jws.decode(jwsSigned);
}

module.exports = {
  toJson: toJson,
  validarSimple:validarSimple,
  recuperarCertificados: recuperarCertificados,
  recuperarCertificadosSubject: recuperarCertificadosSubject
};
