plugins {
    `lib`
}

dependencies {
    api(project(":smime-simple"))
    api("org.bouncycastle:bcprov-jdk15on:1.70")
    api("org.bouncycastle:bcpkix-jdk15on:1.70")
}
