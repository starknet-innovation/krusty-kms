import 'dart:ffi';
import 'dart:io';

import '../exceptions.dart';

DynamicLibrary loadKmsLibrary() {
  final envPath =
      Platform.environment['KMS_LIB_PATH'] ?? Platform.environment['VOLTAIRE_LIB_PATH'];

  if (envPath != null && envPath.isNotEmpty) {
    return DynamicLibrary.open(envPath);
  }

  final String name;
  if (Platform.isMacOS) {
    name = 'libkms.dylib';
  } else if (Platform.isWindows) {
    name = 'kms.dll';
  } else {
    name = 'libkms.so';
  }

  try {
    return DynamicLibrary.open(name);
  } on ArgumentError {
    throw KmsException(-10, 'Could not locate $name; set KMS_LIB_PATH');
  }
}
