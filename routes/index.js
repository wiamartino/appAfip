var express = require('express');
var router = express.Router();
var forge = require('node-forge');
var stream = require('stream');
var archiver = require('archiver');




/* GET home page. */
router.get('/', function (req, res, next) {
  res.render('index');
});


router.post('/getCerts', function (req, res, next) {

  var keys = forge.pki.rsa.generateKeyPair(2048);
  var csr = forge.pki.createCertificationRequest();
  var cuit = 'CUIT ' + req.body.param_snumber;

  csr.publicKey = keys.publicKey;


  csr.setSubject([
    {
      name: 'countryName',
      value: req.body.param_c
    },
    {
      name: 'organizationName',
      value: req.body.param_o
    },
    {
      name: 'commonName',
      value: req.body.param_cn
    },

    {
      name: 'serialName',
      value: cuit
    }

  ]);

  csr.sign(keys.privateKey);

  var verified = csr.verify();

  var pem = forge.pki.certificationRequestToPem(csr);

  var privadapem = forge.pki.privateKeyToPem(keys.privateKey);

  // ARCHIVOS
  var archive = archiver('zip');

  archive.on('error', function (err) {
    res.status(500).send({ error: err.message });
  });


  archive.on('end', function () {
    console.log('Archive wrote %d bytes', archive.pointer());
  });

  var nombreZip = 'certificados - ' + req.body.param_o + '.zip';

  res.attachment(nombreZip);

  archive.pipe(res);
  archive.append(privadapem, { name: 'privada.key' });
  archive.append(pem, { name: 'certificado.csr' });
  archive.finalize();

});


router.post('/getP12', function (req, res, next) {

// Obtengo archivos 
  var privateKey = forge.pki.privateKeyFromPem(req.files.privada.data.toString());
  var cert = forge.pki.certificateFromPem(req.files.certCRT.data.toString());

  var p12Asn1 = forge.pkcs12.toPkcs12Asn1(
    privateKey, cert, req.body.passp12,
    { friendlyName: req.body.userp12, algorithm: '3des' });
    
  var p12Der = forge.asn1.toDer(p12Asn1).getBytes();
  var p12b64 = forge.util.encode64(p12Der);

  var nombreArchivo = req.body.userp12 + "+store.p12";

  var archivo = Buffer.from(p12b64, "base64");
  var readStream = new stream.PassThrough();
  readStream.end(archivo);

  res.setHeader('Content-type', "application/octet-stream");
  res.setHeader("Content-Disposition", "filename=" + nombreArchivo);
  readStream.pipe(res);
 
});


module.exports = router;
