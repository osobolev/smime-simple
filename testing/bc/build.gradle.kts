plugins {
    `lib`
}

dependencies {
    api(project(":smime-simple"))
    api("org.bouncycastle:bcprov-jdk18on:1.77")
    api("org.bouncycastle:bcpkix-jdk18on:1.77")
}
