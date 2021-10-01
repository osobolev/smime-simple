rootProject.name = "smime-simple"

include("smime", "testing/bc", "testing/rand", "testing/test")

project(":smime").name = "smime"
project(":testing/bc").name = "testing-bc"
project(":testing/rand").name = "testing-rand"
project(":testing/test").name = "testing-test"
