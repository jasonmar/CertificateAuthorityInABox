package crypto

import java.nio.file.{Files, Paths}
import java.security.PrivateKey
import java.security.cert.X509Certificate


object DER {
  def write(priv: PrivateKey, name: String): Unit =
    Files.write(Paths.get(name + ".der"), priv.getEncoded)

  def write(cert: X509Certificate, name: String): Unit =
    Files.write(Paths.get(name + ".crt"), cert.getEncoded)
}
