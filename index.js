const jws = require('jws');
const x509 = require('x509.js');
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
  return ("-----BEGIN CERTIFICATE-----\n" + cert.trim() + "\n-----END CERTIFICATE-----");
}

const validarSimple = (jwsSigned) => {
  const certificadosLista = recuperarCertificados(jwsSigned);
  if (!certificadosLista){
    return false;
  }
  const parsedKey = certificadosLista[0];
  const key = new NodeRSA();
  key.importKey({
    n: new Buffer(parsedKey.publicModulus, 'hex'),
    e: parseInt(parseInt(parsedKey.publicExponent, 16))
  }, 'components-public');
  const exportedKey = key.exportKey('public');
  return jws.verify(jwsSigned, 'RS256', exportedKey);
}
const recuperarCertificados = (jwsSigned) => {
  const jwsDecoded = jws.decode(jwsSigned);
  if(!jwsDecoded){
    return null;
  }
  const certificados = jwsDecoded.header.x5c;
  return certificados.map(x => {
    return x509.parseCert(_x5c_to_cert(x));
  });

}
const recuperarCertificadosSubject = (jwsSigned) => {
  var listaCertificados = recuperarCertificados(jwsSigned);
  if (!listaCertificados){
    return 'no existe certificado'
  }
  return listaCertificados.map(x => x.subject);
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
