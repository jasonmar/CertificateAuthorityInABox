package crypto

import java.nio.file.Paths
import java.security.Security

import org.bouncycastle.jce.provider.BouncyCastleProvider

object Main {
  def main(args: Array[String]) {
    Security.addProvider(new BouncyCastleProvider())

    ConfigParser.parse(args, Config()) match {
      case Some(c) =>
        if (!Paths.get(c.caKey).toFile.exists())
          CA.generateNew()
        else
          System.out.println("loading CA key from " + c.caKey)

        CA.generateKeyAndSignCert(c)

        CA.createKeyStore(c)
      case _ =>
    }
  }
}
