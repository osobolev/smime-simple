plugins {
    id("base-lib")
}

group = "io.github.osobolev"
version = "1.3"

(publishing.publications["mavenJava"] as MavenPublication).pom {
    name.set("smime-simple")
    description.set("Simple S/MIME library not dependent on Java Security")
    url.set("https://github.com/osobolev/smime-simple")
    licenses {
        license {
            name.set("The Apache License, Version 2.0")
            url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
        }
    }
    developers {
        developer {
            name.set("Oleg Sobolev")
            organizationUrl.set("https://github.com/osobolev")
        }
    }
    scm {
        connection.set("scm:git:https://github.com/osobolev/smime-simple.git")
        developerConnection.set("scm:git:https://github.com/osobolev/smime-simple.git")
        url.set("https://github.com/osobolev/smime-simple")
    }
}
