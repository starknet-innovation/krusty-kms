plugins {
    java
    kotlin("jvm") version "2.4.10"
}

group = "io.krustykms"
version = "0.1.0"

repositories {
    mavenCentral()
}

dependencies {
    implementation(kotlin("stdlib"))
    testImplementation("org.junit.jupiter:junit-jupiter:6.1.3")
}

tasks.test {
    useJUnitPlatform()
}
