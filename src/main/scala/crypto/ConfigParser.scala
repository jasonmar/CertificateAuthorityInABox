package crypto

object ConfigParser extends scopt.OptionParser[Config]("ca") {
  opt[String]("cn").action((x,c) => c.copy(cn=x))
  opt[String]("entity").action((x,c) => c.copy(entity=x))
  opt[String]("city").action((x,c) => c.copy(city=x))
  opt[String]("state").action((x,c) => c.copy(state=x))
  opt[String]("country").action((x,c) => c.copy(country=x))
  opt[String]("domain").action((x,c) => c.copy(hostname=x))
  opt[Seq[String]]("altNames").action((x,c) => c.copy(altNames=x))
  opt[Seq[String]]("ipAddrs").action((x,c) => c.copy(ipAddrs=x))
  opt[String]("name").action((x,c) => c.copy(name=x))
  opt[String]("caCert").action((x,c) => c.copy(caCert=x))
  opt[String]("caKey").action((x,c) => c.copy(caKey=x))
}
