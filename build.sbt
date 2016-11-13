name := "certificate-authority-in-a-box"

version := "1.0"

scalaVersion := "2.11.8"

libraryDependencies += "org.bouncycastle" % "bcprov-jdk15on" % "1.55"

libraryDependencies += "org.bouncycastle" % "bcpkix-jdk15on" % "1.55"

libraryDependencies += "org.scalatest" % "scalatest_2.11" % "2.2.4" % "test"

mainClass in (Compile, run) := Some("crypto.Main")
