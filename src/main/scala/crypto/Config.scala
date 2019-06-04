package crypto



case class Config(
                   cn: String = "localhost",
                   entity: String = "Developer",
                   city: String = "Mountain View",
                   state: String = "CA",
                   country: String = "US",
                   hostname: String = "localhost",
                   altNames: Seq[String] = Seq("localhost"),
                   ipAddrs: Seq[String] = Seq("127.0.0.1"),
                   name: String = "localhost",
                   caCert: String = "ca.pem",
                   caKey: String = "ca.key"
                 )