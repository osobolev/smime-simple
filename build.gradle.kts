plugins {
    id("com.github.ben-manes.versions") version "0.53.0"
}

fun requiredMajor(mod: ModuleComponentIdentifier): String {
    if (mod.group == "com.sun.mail") return "1." // Version >= 2 uses jakarta namespace
    return ""
}

tasks.withType(com.github.benmanes.gradle.versions.updates.DependencyUpdatesTask::class).configureEach {
    rejectVersionIf {
        !candidate.version.startsWith(requiredMajor(candidate))
    }
}
