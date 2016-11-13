package crypto

import java.io.{ByteArrayInputStream, FileWriter}
import java.math.BigInteger
import java.nio.file.{Files, Paths}
import java.security._
import java.util.Date
import java.security.cert.X509Certificate

import org.bouncycastle.asn1._
import org.bouncycastle.asn1.x509._
import org.bouncycastle.cert.{X509CertificateHolder, X509v3CertificateBuilder}
import org.bouncycastle.asn1.x500._
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.cert.bc.BcX509ExtensionUtils
import org.bouncycastle.cert.jcajce.{JcaX509CertificateConverter, JcaX509v3CertificateBuilder}
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.util.IPAddress


object Crypto {

  sealed trait RSAKeySize { val bits: Int }
  case object RSA4096 extends RSAKeySize { val bits = 4096 }
  case object RSA2048 extends RSAKeySize { val bits = 2048 }
  case object RSA1024 extends RSAKeySize { val bits = 1024 }

  /** Generate RSA KeyPair */
  def genRSA(keySize: RSAKeySize = RSA4096): KeyPair = {
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME)
    keyPairGenerator.initialize(keySize.bits , new SecureRandom())
    keyPairGenerator.generateKeyPair()
  }

  def createSubjectKeyIdentifier(key: Key): SubjectKeyIdentifier = {
      val is: ASN1InputStream = new ASN1InputStream(new ByteArrayInputStream(key.getEncoded))
      val seq: ASN1Sequence = is.readObject.asInstanceOf[ASN1Sequence]
      val info: SubjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(seq)
      new BcX509ExtensionUtils().createSubjectKeyIdentifier(info)
  }

  def signCertificate(cb: X509v3CertificateBuilder, key: PrivateKey): X509Certificate = {
    val cs: ContentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider(BouncyCastleProvider.PROVIDER_NAME).build(key)
    val cc: JcaX509CertificateConverter = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
    cc.getCertificate(cb.build(cs))
  }

  def createRootCACert(publicKey: PublicKey, serial: Long, privateKey: PrivateKey, issuerName: X500Name, daysToExpiration: Int): X509Certificate = {
    createCACert(publicKey, serial, privateKey, issuerName, issuerName, daysToExpiration)
  }

  def mkX500Name(cn: String, ous: Vector[String], org: String, countryCode: String): X500Name = {
    val namebuilder = new X500NameBuilder(X500Name.getDefaultStyle)
    namebuilder.addRDN(BCStyle.CN, cn)
    ous.foreach{ou => namebuilder.addRDN(BCStyle.OU, ou)}
    namebuilder.addRDN(BCStyle.O, org)
    namebuilder.addRDN(BCStyle.C, countryCode)
    namebuilder.build()
  }

  /**  Example:
    *  CN = www.verisign.com
    *  OU = Enterprise IT
    *  O = Verisign, Inc
    *  STREET = 12061 Bluemont Way
    *  L = Reston
    *  S = Virginia
    *  PostalCode = 20190
    *  C = US
    *  SERIALNUMBER = 2497886
    *  2.5.4.15 = Private Organization
    *  1.3.6.1.4.1.311.60.2.1.2 = Delaware
    *  1.3.6.1.4.1.311.60.2.1.3 = US
    */
  def mkX500Name2(cn: String, ous: Vector[String], orgName: String, street: String, l: String, state: String, postalCode: String, countryCode: String, serial: Long): X500Name = {
    val namebuilder = new X500NameBuilder(X500Name.getDefaultStyle)
    namebuilder.addRDN(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.60.2.1.3"), countryCode)
    namebuilder.addRDN(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.60.2.1.2"), state)
    namebuilder.addRDN(new ASN1ObjectIdentifier("2.5.4.15"), "Private Organization")
    namebuilder.addRDN(BCStyle.SERIALNUMBER, serial.toString)
    namebuilder.addRDN(BCStyle.C, countryCode)
    namebuilder.addRDN(BCStyle.POSTAL_CODE, postalCode)
    namebuilder.addRDN(BCStyle.ST, state)
    namebuilder.addRDN(BCStyle.L, street)
    namebuilder.addRDN(BCStyle.STREET, street)
    namebuilder.addRDN(BCStyle.O, orgName)
    ous.foreach{ou => namebuilder.addRDN(BCStyle.OU, ou)}
    namebuilder.addRDN(BCStyle.CN, cn)
    namebuilder.build()
  }

  def createCACert(publicKey: PublicKey, serial: Long, caPrivateKey: PrivateKey, issuerName: X500Name, subjectName: X500Name, daysToExpiration: Int): X509Certificate = {
    val bigSerial: BigInteger = BigInteger.valueOf(serial)
    val ONE_DAY_MILLIS: Long = 1000 * 60 * 60 * 24
    val start = System.currentTimeMillis() - ONE_DAY_MILLIS
    val notBefore = new Date(start)
    val notAfter = new Date(start + ONE_DAY_MILLIS * daysToExpiration)
    val builder: X509v3CertificateBuilder = new JcaX509v3CertificateBuilder(issuerName, bigSerial, notBefore, notAfter, subjectName, publicKey)
    builder.addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyIdentifier(publicKey))
    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
    val usage: KeyUsage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment | KeyUsage.cRLSign)
    builder.addExtension(Extension.keyUsage, false, usage)
    val purposes: ASN1EncodableVector = new ASN1EncodableVector
    purposes.add(KeyPurposeId.id_kp_serverAuth)
    purposes.add(KeyPurposeId.id_kp_clientAuth)
    purposes.add(KeyPurposeId.anyExtendedKeyUsage)
    builder.addExtension(Extension.extendedKeyUsage, false, new DERSequence(purposes))
    val cert: X509Certificate = signCertificate(builder, caPrivateKey)
    cert
  }

  def validateCert(cert: X509Certificate, publicKey: PublicKey): Unit = {
    cert.checkValidity(new Date)
    cert.verify(publicKey)
  }

  def createClientCert(clientCN: X500Name, serial: Long, publicKey: PublicKey, caCert: X509Certificate, caPrivateKey: PrivateKey, caPublicKey: PublicKey, domain: String, subjectAlternativeNameDomains: Vector[String], ipAddresses: Vector[String], daysToExpiration: Int): X509Certificate = {

    val issuer: X500Name = new X509CertificateHolder(caCert.getEncoded).getSubject
    val bigSerial: BigInteger = BigInteger.valueOf(serial)

    val ONE_DAY_MILLIS: Long = 1000 * 60 * 60 * 24
    val start = System.currentTimeMillis() - ONE_DAY_MILLIS
    val notBefore = new Date(start)
    val notAfter = new Date(start + ONE_DAY_MILLIS * daysToExpiration)
    val builder: X509v3CertificateBuilder = new JcaX509v3CertificateBuilder(issuer, bigSerial, notBefore, notAfter, clientCN, publicKey)
    builder.addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyIdentifier(publicKey))
    builder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false))

    val usage: KeyUsage = new KeyUsage(KeyUsage.dataEncipherment | KeyUsage.digitalSignature | KeyUsage.nonRepudiation)
    builder.addExtension(Extension.keyUsage, false, usage)

    val sanDomains: Vector[GeneralName] = Vector[GeneralName](new GeneralName(GeneralName.dNSName,domain)) ++ subjectAlternativeNameDomains.map(d => new GeneralName(GeneralName.dNSName, d))
    val sanIPs: Vector[GeneralName] = ipAddresses.filter(isValidIPAddress).map(ip => new GeneralName(GeneralName.iPAddress, ip))
    val sans = sanDomains ++ sanIPs
    if (sans.nonEmpty) {
      val derSeq = new GeneralNames(sans.toArray)
      builder.addExtension(Extension.subjectAlternativeName, false, derSeq)
    }

    val purposes: ASN1EncodableVector = new ASN1EncodableVector
    purposes.add(KeyPurposeId.id_kp_serverAuth)
    purposes.add(KeyPurposeId.id_kp_clientAuth)
    purposes.add(KeyPurposeId.id_kp_codeSigning)
    purposes.add(KeyPurposeId.id_kp_emailProtection)
    purposes.add(KeyPurposeId.anyExtendedKeyUsage)
    builder.addExtension(Extension.extendedKeyUsage, false, new DERSequence(purposes))

    val cert: X509Certificate = signCertificate(builder, caPrivateKey)
    cert
  }

  def isValidIPAddress(ip: String): Boolean = {
    IPAddress.isValidIPv6WithNetmask(ip) || IPAddress.isValidIPv6(ip) || IPAddress.isValidIPv4WithNetmask(ip) || IPAddress.isValidIPv4(ip)
  }

  def saveCertificateAsPEMFile(x509Certificate: X509Certificate, filename: String): Unit = {
    new JcaPEMWriter(new FileWriter(filename)).writeObject(x509Certificate)
  }

  def write(bytes: Array[Byte], of: String): Unit = {
    val path = Paths.get(of)
    Files.write(path, bytes)
  }
}
