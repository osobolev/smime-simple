plugins {
    `lib`
}

dependencies {
    manualImplementation("org.bouncycastle:bcmail-jdk18on:1.77")
    manualImplementation(project(":smime-simple"))
    manualImplementation(project(":smime-testing-bc"))
    manualImplementation(project(":smime-testing-rand"))
}
