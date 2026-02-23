# krusty-kms-jvm

Shared JNI-backed JVM package for Java and Kotlin.

- `src/main/java/io/krustykms`: Java API.
- `src/main/kotlin/io/krustykms`: Kotlin extensions.
- `src/main/c/kms_jni.c`: JNI bridge to `libkms`.

CI builds with Gradle (without a checked-in wrapper) and validates Java/Kotlin compilation.
