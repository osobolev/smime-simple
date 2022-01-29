plugins {
    `lib`
}

dependencies {
    testImplementation("org.bouncycastle:bcmail-jdk15on:1.70")
    testImplementation(project(":smime-simple"))
    testImplementation(project(":smime-testing-bc"))
    testImplementation(project(":smime-testing-rand"))
}
