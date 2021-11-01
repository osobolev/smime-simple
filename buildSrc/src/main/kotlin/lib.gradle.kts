plugins {
    `java-library`
    `maven-publish`
    `signing`
}

group = "io.github.osobolev"
version = "1.1"

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    withSourcesJar()
    withJavadocJar()
}

sourceSets {
    main {
        java.srcDir("src")
    }
    test {
        java.srcDir("test")
    }
}

tasks {
    withType(JavaCompile::class) {
        options.encoding = "UTF-8"
    }
}

repositories {
    mavenCentral()
}

tasks.javadoc {
    (options as CoreJavadocOptions).addBooleanOption("Xdoclint:none", true)
    options.quiet()
}

tasks.jar {
    manifest {
        attributes("Implementation-Version" to project.version)
    }
}

val sonatypeUsername: String? by project
val sonatypePassword: String? by project

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            pom {
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
            from(components["java"])
        }
    }

    repositories {
        maven {
            url = uri("https://s01.oss.sonatype.org/service/local/staging/deploy/maven2/")
            credentials {
                username = sonatypeUsername
                password = sonatypePassword
            }
        }
    }
}

signing {
    sign(publishing.publications["mavenJava"])
}

tasks.named("clean").configure {
    doLast {
        project.delete("$projectDir/out")
    }
}
