import 'dart:typed_data';

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

int _bytesHash(Uint8List bytes) {
  // FNV-1a inspired hash
  var hash = 0x811c9dc5;
  for (final b in bytes) {
    hash ^= b;
    hash = (hash * 0x01000193) & 0xFFFFFFFF;
  }
  return hash;
}

class Felt {
  final Uint8List _bytes;

  Felt(Uint8List bytes)
      : _bytes = Uint8List.fromList(bytes) {
    if (_bytes.length != 32) {
      throw ArgumentError('Felt must be exactly 32 bytes, got ${_bytes.length}');
    }
  }

  Uint8List get bytes => Uint8List.fromList(_bytes);

  static Felt fromHex(String hex) {
    var h = hex;
    if (h.startsWith('0x') || h.startsWith('0X')) {
      h = h.substring(2);
    }
    if (h.length.isOdd) {
      h = '0$h';
    }
    final raw = Uint8List(h.length ~/ 2);
    for (var i = 0; i < raw.length; i++) {
      raw[i] = int.parse(h.substring(i * 2, i * 2 + 2), radix: 16);
    }
    // Left-pad to 32 bytes
    final padded = Uint8List(32);
    padded.setRange(32 - raw.length, 32, raw);
    return Felt(padded);
  }

  String toHex() {
    final sb = StringBuffer('0x');
    var leadingZero = true;
    for (final b in _bytes) {
      if (leadingZero && b == 0) continue;
      leadingZero = false;
      sb.write(b.toRadixString(16).padLeft(2, '0'));
    }
    if (leadingZero) sb.write('0');
    return sb.toString();
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) || (other is Felt && _bytesEqual(_bytes, other._bytes));

  @override
  int get hashCode => _bytesHash(_bytes);

  @override
  String toString() => 'Felt(${toHex()})';
}

class AffinePoint {
  final Felt x;
  final Felt y;

  const AffinePoint(this.x, this.y);

  @override
  bool operator ==(Object other) =>
      identical(this, other) || (other is AffinePoint && x == other.x && y == other.y);

  @override
  int get hashCode => Object.hash(x, y);

  @override
  String toString() => 'AffinePoint(x: $x, y: $y)';
}

class ProjectivePoint {
  final Felt x;
  final Felt y;
  final Felt z;

  const ProjectivePoint(this.x, this.y, this.z);

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is ProjectivePoint && x == other.x && y == other.y && z == other.z);

  @override
  int get hashCode => Object.hash(x, y, z);

  @override
  String toString() => 'ProjectivePoint(x: $x, y: $y, z: $z)';
}

class TongoKeyPair {
  final Felt privateKey;
  final ProjectivePoint publicKey;

  const TongoKeyPair(this.privateKey, this.publicKey);

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is TongoKeyPair && privateKey == other.privateKey && publicKey == other.publicKey);

  @override
  int get hashCode => Object.hash(privateKey, publicKey);

  @override
  String toString() => 'TongoKeyPair(privateKey: $privateKey, publicKey: $publicKey)';
}

class NostrKeyPair {
  final Uint8List privateKey;
  final Uint8List publicKeyXonly;

  NostrKeyPair(Uint8List privateKey, Uint8List publicKeyXonly)
      : privateKey = Uint8List.fromList(privateKey),
        publicKeyXonly = Uint8List.fromList(publicKeyXonly);

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is NostrKeyPair &&
          _bytesEqual(privateKey, other.privateKey) &&
          _bytesEqual(publicKeyXonly, other.publicKeyXonly));

  @override
  int get hashCode => Object.hash(_bytesHash(privateKey), _bytesHash(publicKeyXonly));

  @override
  String toString() => 'NostrKeyPair(privateKey: [${privateKey.length} bytes], '
      'publicKeyXonly: [${publicKeyXonly.length} bytes])';
}

class AccountHandle {
  final int rawValue;

  const AccountHandle(this.rawValue);

  @override
  bool operator ==(Object other) =>
      identical(this, other) || (other is AccountHandle && rawValue == other.rawValue);

  @override
  int get hashCode => rawValue.hashCode;

  @override
  String toString() => 'AccountHandle($rawValue)';
}

class AccountState {
  final int balanceLow;
  final int balanceHigh;
  final int pendingBalanceLow;
  final int pendingBalanceHigh;
  final int nonce;

  const AccountState({
    required this.balanceLow,
    required this.balanceHigh,
    required this.pendingBalanceLow,
    required this.pendingBalanceHigh,
    required this.nonce,
  });

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is AccountState &&
          balanceLow == other.balanceLow &&
          balanceHigh == other.balanceHigh &&
          pendingBalanceLow == other.pendingBalanceLow &&
          pendingBalanceHigh == other.pendingBalanceHigh &&
          nonce == other.nonce);

  @override
  int get hashCode =>
      Object.hash(balanceLow, balanceHigh, pendingBalanceLow, pendingBalanceHigh, nonce);

  @override
  String toString() =>
      'AccountState(balanceLow: $balanceLow, balanceHigh: $balanceHigh, '
      'pendingBalanceLow: $pendingBalanceLow, pendingBalanceHigh: $pendingBalanceHigh, '
      'nonce: $nonce)';
}

class EthSignature {
  final Felt rLow;
  final Felt rHigh;
  final Felt sLow;
  final Felt sHigh;
  final Felt v;

  const EthSignature({
    required this.rLow,
    required this.rHigh,
    required this.sLow,
    required this.sHigh,
    required this.v,
  });

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is EthSignature &&
          rLow == other.rLow &&
          rHigh == other.rHigh &&
          sLow == other.sLow &&
          sHigh == other.sHigh &&
          v == other.v);

  @override
  int get hashCode => Object.hash(rLow, rHigh, sLow, sHigh, v);

  @override
  String toString() =>
      'EthSignature(rLow: $rLow, rHigh: $rHigh, sLow: $sLow, sHigh: $sHigh, v: $v)';
}
