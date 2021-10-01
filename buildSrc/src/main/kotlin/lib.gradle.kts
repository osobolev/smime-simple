plugins {
    `java-library`
    `maven-publish`
}

group = "com.github.osobolev.smime-simple"
version = "1.1"

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    withSourcesJar()
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

tasks.jar {
    manifest {
        attributes("Implementation-Version" to project.version)
    }
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
        }
    }
}

tasks.named("clean").configure {
    doLast {
        project.delete("$projectDir/out")
    }
}
