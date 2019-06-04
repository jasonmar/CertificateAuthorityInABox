package crypto

import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security._
import java.security.cert.X509Certificate
import java.util.Date

import org.bouncycastle.asn1._
import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.asn1.x500._
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509._
import org.bouncycastle.cert.bc.BcX509ExtensionUtils
import org.bouncycastle.cert.jcajce.{JcaX509CertificateConverter, JcaX509v3CertificateBuilder}
import org.bouncycastle.cert.{X509CertificateHolder, X509v3CertificateBuilder}
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.generators.ECKeyPairGenerator
import org.bouncycastle.crypto.params.{ECDomainParameters, ECKeyGenerationParameters}
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.util.IPAddress


object Crypto {

  /** Generate RSA KeyPair */
  def genRSA(): KeyPair = {
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME)
    keyPairGenerator.initialize(2048, new SecureRandom())
    keyPairGenerator.generateKeyPair()
  }

  def genECC(): AsymmetricCipherKeyPair = {
    val ecp = SECNamedCurves.getByName("secp256r1")
    val domainParams = new ECDomainParameters(ecp.getCurve, ecp.getG, ecp.getN, ecp.getH, ecp.getSeed)
    val keyGenParams = new ECKeyGenerationParameters(domainParams, new SecureRandom())
    val generator = new ECKeyPairGenerator()
    generator.init(keyGenParams)
    generator.generateKeyPair
  }

  def createSubjectKeyIdentifier(key: Key): SubjectKeyIdentifier = {
    val is: ASN1InputStream = new ASN1InputStream(new ByteArrayInputStream(key.getEncoded))
    val seq: ASN1Sequence = is.readObject.asInstanceOf[ASN1Sequence]
    val info: SubjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(seq)
    new BcX509ExtensionUtils().createSubjectKeyIdentifier(info)
  }

  def signCertificate(cb: X509v3CertificateBuilder, key: PrivateKey): X509Certificate =
    new JcaX509CertificateConverter()
      .getCertificate(cb.build(new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(key)))

  def createRootCACert(publicKey: PublicKey, serial: Long, privateKey: PrivateKey, issuerName: X500Name, daysToExpiration: Int): X509Certificate =
    createCACert(publicKey, serial, privateKey, issuerName, issuerName, daysToExpiration)

  def mkX500Name(cn: String, org: String, countryCode: String): X500Name =
    new X500NameBuilder(X500Name.getDefaultStyle)
      .addRDN(BCStyle.C, countryCode)
      .addRDN(BCStyle.O, org)
      .addRDN(BCStyle.CN, cn)
      .build()

  def mkX500Name2(cn: String, entity: String, city: String, state: String, countryCode: String): X500Name =
    new X500NameBuilder(X500Name.getDefaultStyle)
      .addRDN(BCStyle.C, countryCode)
      .addRDN(BCStyle.ST, state)
      .addRDN(BCStyle.L, city)
      .addRDN(BCStyle.O, entity)
      .addRDN(BCStyle.CN, cn)
      .build()

  def createCACert(publicKey: PublicKey,
                   serial: Long,
                   caPrivateKey: PrivateKey,
                   issuerName: X500Name,
                   subjectName: X500Name,
                   daysToExpiration: Int): X509Certificate = {
    val bigSerial: BigInteger = BigInteger.valueOf(serial)
    val ONE_DAY_MILLIS: Long = 1000 * 60 * 60 * 24
    val start = System.currentTimeMillis() - ONE_DAY_MILLIS
    val notBefore = new Date(start)
    val notAfter = new Date(start + ONE_DAY_MILLIS * daysToExpiration)
    val usage: KeyUsage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment | KeyUsage.cRLSign)

    val builder: X509v3CertificateBuilder = new JcaX509v3CertificateBuilder(issuerName, bigSerial, notBefore, notAfter, subjectName, publicKey)
      .addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyIdentifier(publicKey))
      .addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
      .addExtension(Extension.keyUsage, false, usage)
      .addExtension(Extension.extendedKeyUsage, false, purposes(KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth, KeyPurposeId.anyExtendedKeyUsage))
    signCertificate(builder, caPrivateKey)
  }

  def validateCert(cert: X509Certificate, publicKey: PublicKey): Unit = {
    cert.checkValidity(new Date)
    cert.verify(publicKey)
  }

  def createClientCert(clientCN: X500Name,
                       serial: Long,
                       publicKey: PublicKey,
                       caCert: X509Certificate,
                       caKey: PrivateKey,
                       domain: String,
                       subjectAlternativeNameDomains: Seq[String],
                       ipAddresses: Seq[String],
                       daysToExpiration: Int): X509Certificate = {
    val issuer: X500Name = new X509CertificateHolder(caCert.getEncoded).getSubject
    val bigSerial: BigInteger = BigInteger.valueOf(serial)

    val ONE_DAY_MILLIS: Long = 1000 * 60 * 60 * 24
    val start = System.currentTimeMillis() - ONE_DAY_MILLIS
    val notBefore = new Date(start)
    val notAfter = new Date(start + ONE_DAY_MILLIS * daysToExpiration)
    val usage: KeyUsage = new KeyUsage(KeyUsage.digitalSignature)
    val builder: X509v3CertificateBuilder = new JcaX509v3CertificateBuilder(issuer, bigSerial, notBefore, notAfter, clientCN, publicKey)
      .addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyIdentifier(publicKey))
      .addExtension(Extension.basicConstraints, false, new BasicConstraints(false))
      .addExtension(Extension.keyUsage, false, usage)
      .addExtension(Extension.extendedKeyUsage, false, purposes(KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth))

    val sanDomains = Seq[GeneralName](
        new GeneralName(GeneralName.dNSName,domain)
      ) ++ subjectAlternativeNameDomains
        .map(d => new GeneralName(GeneralName.dNSName, d))
    val sanIPs = ipAddresses.filter(isValidIPAddress).map(ip => new GeneralName(GeneralName.iPAddress, ip))
    val sans = sanDomains ++ sanIPs
    if (sans.nonEmpty) {
      builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(sans.toArray))
    }
    signCertificate(builder, caKey)
  }

  def purposes(ids: KeyPurposeId*): DERSequence =
    new DERSequence(ids.foldLeft(new ASN1EncodableVector){(a,b) => a.add(b); a})

  def isValidIPAddress(ip: String): Boolean = {
    IPAddress.isValidIPv6WithNetmask(ip) || IPAddress.isValidIPv6(ip) || IPAddress.isValidIPv4WithNetmask(ip) || IPAddress.isValidIPv4(ip)
  }
}
