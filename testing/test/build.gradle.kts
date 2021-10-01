plugins {
    `lib`
}

dependencies {
    testImplementation("org.bouncycastle:bcmail-jdk15on:1.69")
    testImplementation(project(":smime"))
    testImplementation(project(":testing-bc"))
    testImplementation(project(":testing-rand"))
}
