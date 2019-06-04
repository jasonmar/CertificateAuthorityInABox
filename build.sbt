name := "certificate-authority-in-a-box"

version := "1.0"

scalaVersion := "2.11.12"

libraryDependencies += "org.bouncycastle" % "bcprov-jdk15on" % "1.55"

libraryDependencies += "org.bouncycastle" % "bcpkix-jdk15on" % "1.55"

libraryDependencies += "com.google.guava" % "guava" % "27.1-jre"

libraryDependencies += "com.github.scopt" %% "scopt" % "3.7.1"

libraryDependencies += "org.scalatest" %% "scalatest" % "2.2.4" % "test"

mainClass in (Compile, run) := Some("crypto.Main")
