const express = require('express');
const router = express.Router();
const forge = require('node-forge');
const archiver = require('archiver');

router.get('/', (req, res) => {
  res.render('index');
});

router.post('/getCerts', (req, res) => {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const csr = forge.pki.createCertificationRequest();
  const cuit = 'CUIT ' + req.body.param_snumber;

  csr.publicKey = keys.publicKey;

  csr.setSubject([
    { name: 'countryName', value: req.body.param_c, type: 'countryName' },
    { name: 'organizationName', value: req.body.param_o, type: 'organizationName' },
    { name: 'commonName', value: req.body.param_cn, type: 'commonName' },
    { name: 'serialName', value: cuit, type: 'serialName' }
  ]);

  csr.sign(keys.privateKey);

  const pem = forge.pki.certificationRequestToPem(csr);
  const privadapem = forge.pki.privateKeyToPem(keys.privateKey);

  const archive = archiver('zip');

  archive.on('error', (err) => {
    res.status(500).send({ error: err.message });
  });

  archive.on('end', () => {
    console.log('Archive wrote %d bytes', archive.pointer());
  });

  const nombreZip = `certificados - ${req.body.param_o}.zip`;

  res.attachment(nombreZip);
  archive.pipe(res);
  archive.append(privadapem, { name: 'privada.key' });
  archive.append(pem, { name: 'certificado.csr' });
  archive.finalize();
});

router.post('/getP12', (req, res) => {
  const privateKey = forge.pki.privateKeyFromPem(req.files.privada.data.toString());
  const cert = forge.pki.certificateFromPem(req.files.certCRT.data.toString());

  const p12Asn1 = forge.pkcs12.toPkcs12Asn1(
    privateKey, cert, req.body.passp12,
    { friendlyName: req.body.userp12, algorithm: '3des' }
  );

  const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
  const p12b64 = forge.util.encode64(p12Der);
  const nombreArchivo = `${req.body.userp12}+store.p12`;
  const archivo = Buffer.from(p12b64, 'base64');

  res.setHeader('Content-type', 'application/octet-stream');
  res.setHeader('Content-Disposition', `filename=${nombreArchivo}`);
  res.send(archivo);
});

module.exports = router;