plugins {
    `lib`
}

dependencies {
    api(project(":smime"))
    api("org.bouncycastle:bcprov-jdk15on:1.69")
    api("org.bouncycastle:bcpkix-jdk15on:1.69")
}
