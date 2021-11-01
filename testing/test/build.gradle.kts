plugins {
    `lib`
}

dependencies {
    testImplementation("org.bouncycastle:bcmail-jdk15on:1.69")
    testImplementation(project(":smime-simple"))
    testImplementation(project(":smime-testing-bc"))
    testImplementation(project(":smime-testing-rand"))
}
