package crypto

import java.security.Security
import crypto.Crypto._
import org.bouncycastle.jce.provider.BouncyCastleProvider

object Main extends App {

  Security.addProvider(new BouncyCastleProvider())

  val rootCN = mkX500Name(
    "Weyland-Yutani Class 3 Public Primary Certification Authority - G5",
    Vector("(c) 2016 Weyland-Yutani, Inc. - For authorized use only",
      "Weyland-Yutani Trust Network"),
    "Weyland-Yutani, Inc.",
    "US"
  )
  val intCN = mkX500Name(
    "Weyland-Yutani Class 3 EV SSL CA - G3",
    Vector("Weyland-Yutani Trust Network"),
    "Weyland-Yutani Corporation",
    "US"
  )
  val clientCN = mkX500Name2(
    "*.compute-1.amazonaws.com",Vector("Enterprise IT"),
    "Weyland-Yutani, Inc",
    "1 Weyland-Yutani Way",
    "New York",
    "New York",
    "10003",
    "US",
    1
  )

  val rootKey = genRSA(RSA2048)
  val rootCert = createRootCACert(rootKey.getPublic, 1L, rootKey.getPrivate, rootCN, 365*20)
  write(rootKey.getPrivate.getEncoded, "root_rsa.der")
  write(rootKey.getPublic.getEncoded, "root_pub.der")
  write(rootCert.getEncoded, "root.der")

  val intKey = genRSA(RSA2048)
  val intCert = createCACert(intKey.getPublic, 1L, rootKey.getPrivate, rootCN, intCN, 365*2)
  write(intKey.getPrivate.getEncoded, "int_rsa.der")
  write(intKey.getPublic.getEncoded, "int_pub.der")
  write(intCert.getEncoded, "int.der")

  val clientKey = genRSA(RSA2048)
  val clientCert = createClientCert(clientCN, 1L, clientKey.getPublic, intCert, intKey.getPrivate, intKey.getPublic, "*.compute-1.amazonaws.com", Vector("localhost"), Vector("127.0.0.1"), 365*2)
  write(clientKey.getPrivate.getEncoded, "localhost_rsa.der")
  write(clientKey.getPublic.getEncoded, "localhost_pub.der")
  write(clientCert.getEncoded, "localhost.der")


}
