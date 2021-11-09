plugins {
    `lib`
}

dependencies {
    testImplementation(project(":smime-simple"))
    testImplementation(project(":smime-testing-bc"))
    testImplementation(project(":smime-testing-rand"))
}
