plugins {
    `lib`
}

dependencies {
    api(project(":smime-simple"))
    api("org.bouncycastle:bcprov-jdk18on:1.84")
    api("org.bouncycastle:bcpkix-jdk18on:1.84")
}
