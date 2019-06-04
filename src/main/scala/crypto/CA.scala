package crypto

import java.security.PrivateKey
import java.security.cert.X509Certificate

import crypto.Crypto._

import scala.util.Random

object CA {
  def generateNew(): Unit = {
    System.out.println("Generating CA keys and certificates")
    val rootCN = mkX500Name(
      "Class 3 Public Primary Certification Authority - G5",
      "Cloud Trust Network",
      "US"
    )

    val rootKey = genRSA()
    val rootCert = createRootCACert(rootKey.getPublic, Random.nextLong(),
      rootKey.getPrivate, rootCN, 365 * 10)

    val intCN = mkX500Name(
      "Class 3 EV SSL CA - G3",
      "Cloud Trust Network",
      "US"
    )
    val intKey = genRSA()
    val intCert = createCACert(intKey.getPublic, Random.nextLong(),
      rootKey.getPrivate, rootCN, intCN, 365 * 2)

    PEM.write(Seq(intCert, rootCert))
    PEM.write(rootCert, "root")
    DER.write(rootCert, "root")
    PEM.write(rootKey.getPrivate, "root")
    PEM.write(intCert, "ca")
    DER.write(intCert, "ca")
    PEM.write(intKey.getPrivate, "ca")
  }

  def generateKeyAndSignCert(c: Config): Unit = {
    import c._
    generateKeyAndSignCert(
      PEM.read(caCert),
      PEM.readKey(caKey),
      cn,
      entity,
      city, state, country, hostname, altNames, ipAddrs, name
    )
  }

  def generateKeyAndSignCert(caCert: X509Certificate, caKey: PrivateKey, cn: String, entity: String, city: String, state: String, country: String, domain: String, alt: Seq[String], ips: Seq[String], name: String): Unit = {

    val clientCN = mkX500Name2(cn, entity, city, state, country)
    val clientKey = genRSA()
    val cert = createClientCert(clientCN,
      Random.nextLong(),
      clientKey.getPublic,
      caCert,
      caKey,
      domain,
      alt,
      ips,
      365 * 2)

    PEM.write(cert, name)
    DER.write(cert, name)
    PEM.write(clientKey.getPrivate, name)
  }

  def createKeyStore(config: Config): Unit = {
    // TODO create pkcs12 keystore using java.security.KeyStore
    import sys.process._
    val cmd1 = s"""openssl pkcs12 -export -out ${config.name}.p12 -inkey ${config.name}.key -in ${config.name}.pem -name "${config.name}" -certfile ${config.caCert} -caname "ca" -passout pass:changeit"""
    System.out.println(cmd1)
    val result1 = cmd1.!

    System.out.println(result1.toString)

    val cmd2 = s"""openssl pkcs12 -export -in cacerts.pem -caname int -caname root -nokeys -out cacerts.p12 -passout pass:changeit""".stripMargin
    System.out.println(cmd2)
    val result2 = cmd2.!

    System.out.println(result2.toString)
  }
}
