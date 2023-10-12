plugins {
    `lib`
}

dependencies {
    testImplementation("org.bouncycastle:bcmail-jdk18on:1.76")
    testImplementation(project(":smime-simple"))
    testImplementation(project(":smime-testing-bc"))
    testImplementation(project(":smime-testing-rand"))
}
