package crypto

import java.io.{FileInputStream, FileWriter}
import java.nio.file.{Files, Paths}
import java.security.cert.{CertificateFactory, X509Certificate}
import java.security.spec.PKCS8EncodedKeySpec
import java.security.{KeyFactory, PrivateKey}

import com.google.common.base.Charsets
import com.google.common.io.BaseEncoding
import org.bouncycastle.util.io.pem.{PemObject, PemWriter}

object PEM {
  def write(chain: Seq[X509Certificate], path: String = "cacerts.pem"): Unit = {
    val sw = new FileWriter(path)
    val pem = new PemWriter(sw)
    chain.foreach{cert =>
      pem.writeObject(new PemObject("CERTIFICATE", cert.getEncoded))
    }
    pem.flush()
  }

  def write(key: PrivateKey, name: String): Unit = {
    val pem = new PemWriter(new FileWriter(name + ".key"))
    pem.writeObject(new PemObject("RSA PRIVATE KEY", key.getEncoded))
    pem.flush()
  }

  def write(cert: X509Certificate, name: String): Unit = {
    val pem = new PemWriter(new FileWriter(name + ".pem"))
    pem.writeObject(new PemObject("CERTIFICATE", cert.getEncoded))
    pem.flush()
  }

  def read(path: String): X509Certificate =
    CertificateFactory.getInstance("X.509")
      .generateCertificate(new FileInputStream(path))
      .asInstanceOf[X509Certificate]

  def readKey(path: String): PrivateKey = {
    val keyEnc = new String(Files.readAllBytes(Paths.get(path)), Charsets.UTF_8)
      .replace("-----BEGIN RSA PRIVATE KEY-----", "")
      .replace("-----END RSA PRIVATE KEY-----", "")
      .lines.mkString("")
    KeyFactory.getInstance("RSA")
      .generatePrivate(new PKCS8EncodedKeySpec(BaseEncoding.base64().decode(keyEnc)))
  }
}
