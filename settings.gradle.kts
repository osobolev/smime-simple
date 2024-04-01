plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version("0.8.0")
}

rootProject.name = "smime-simple"

include("smime", "testing/bc", "testing/rand", "testing/test")

project(":smime").name = "smime-simple"
project(":testing/bc").name = "smime-testing-bc"
project(":testing/rand").name = "smime-testing-rand"
project(":testing/test").name = "smime-testing-test"
