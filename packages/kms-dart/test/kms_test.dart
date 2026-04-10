import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:krusty_kms/krusty_kms.dart';
import 'package:krusty_kms/src/ffi/types.dart' as c;
import 'package:test/test.dart';

void main() {
  group('FFI struct sizes', () {
    test('KmsFelt is 32 bytes', () {
      expect(sizeOf<c.KmsFelt>(), equals(32));
    });

    test('KmsProjectivePoint is 96 bytes', () {
      expect(sizeOf<c.KmsProjectivePoint>(), equals(96));
    });

    test('KmsAffinePoint is 64 bytes', () {
      expect(sizeOf<c.KmsAffinePoint>(), equals(64));
    });

    test('KmsTongoKeyPair is 128 bytes', () {
      expect(sizeOf<c.KmsTongoKeyPair>(), equals(128));
    });

    test('KmsNostrKeyPair is 64 bytes', () {
      expect(sizeOf<c.KmsNostrKeyPair>(), equals(64));
    });

    test('KmsAccountState is 40 bytes', () {
      expect(sizeOf<c.KmsAccountState>(), equals(40));
    });

    test('KmsEthSignature is 160 bytes', () {
      expect(sizeOf<c.KmsEthSignature>(), equals(160));
    });
  });

  group('Felt', () {
    test('constructor rejects wrong length', () {
      expect(() => Felt(Uint8List(31)), throwsArgumentError);
      expect(() => Felt(Uint8List(33)), throwsArgumentError);
    });

    test('constructor accepts 32 bytes', () {
      final felt = Felt(Uint8List(32));
      expect(felt.bytes.length, equals(32));
    });

    test('fromHex and toHex roundtrip', () {
      final hex = '0x1234abcd';
      final felt = Felt.fromHex(hex);
      expect(felt.toHex(), equals(hex));
    });

    test('fromHex with 0x0', () {
      final felt = Felt.fromHex('0x0');
      expect(felt.toHex(), equals('0x0'));
    });

    test('fromHex without prefix', () {
      final felt = Felt.fromHex('ff');
      expect(felt.toHex(), equals('0xff'));
    });

    test('equality', () {
      final a = Felt.fromHex('0xabcdef');
      final b = Felt.fromHex('0xabcdef');
      final c = Felt.fromHex('0x123456');
      expect(a, equals(b));
      expect(a, isNot(equals(c)));
    });

    test('hashCode consistency', () {
      final a = Felt.fromHex('0xabcdef');
      final b = Felt.fromHex('0xabcdef');
      expect(a.hashCode, equals(b.hashCode));
    });

    test('bytes returns a copy', () {
      final felt = Felt.fromHex('0x1');
      final b1 = felt.bytes;
      final b2 = felt.bytes;
      expect(identical(b1, b2), isFalse);
      expect(b1, equals(b2));
    });
  });

  group('AffinePoint', () {
    test('equality', () {
      final x = Felt.fromHex('0x1');
      final y = Felt.fromHex('0x2');
      final a = AffinePoint(x, y);
      final b = AffinePoint(x, y);
      expect(a, equals(b));
    });
  });

  group('ProjectivePoint', () {
    test('equality', () {
      final x = Felt.fromHex('0x1');
      final y = Felt.fromHex('0x2');
      final z = Felt.fromHex('0x3');
      final a = ProjectivePoint(x, y, z);
      final b = ProjectivePoint(x, y, z);
      expect(a, equals(b));
    });
  });

  group('NostrKeyPair', () {
    test('stores copies', () {
      final priv = Uint8List(32);
      final pub = Uint8List(32);
      priv[0] = 0xff;
      pub[0] = 0xee;
      final kp = NostrKeyPair(priv, pub);
      priv[0] = 0x00; // mutate original
      expect(kp.privateKey[0], equals(0xff)); // copy is untouched
    });
  });

  group('KmsException', () {
    test('toString includes code and message', () {
      final e = KmsException(-1, 'bad hex');
      expect(e.toString(), contains('-1'));
      expect(e.toString(), contains('bad hex'));
    });

    test('error codes are correct', () {
      expect(KmsException.ok, equals(0));
      expect(KmsException.errInvalidHex, equals(-1));
      expect(KmsException.errInternal, equals(-10));
    });
  });

  group('AccountHandle', () {
    test('equality', () {
      expect(AccountHandle(42), equals(AccountHandle(42)));
      expect(AccountHandle(1), isNot(equals(AccountHandle(2))));
    });

    test('toString', () {
      expect(AccountHandle(42).toString(), equals('AccountHandle(42)'));
    });
  });

  group('AccountState', () {
    test('equality', () {
      final a = AccountState(
          balanceLow: 1, balanceHigh: 2, pendingBalanceLow: 3,
          pendingBalanceHigh: 4, nonce: 5);
      final b = AccountState(
          balanceLow: 1, balanceHigh: 2, pendingBalanceLow: 3,
          pendingBalanceHigh: 4, nonce: 5);
      expect(a, equals(b));
    });

    test('toString', () {
      final s = AccountState(
          balanceLow: 10, balanceHigh: 0, pendingBalanceLow: 0,
          pendingBalanceHigh: 0, nonce: 1);
      expect(s.toString(), contains('balanceLow: 10'));
      expect(s.toString(), contains('nonce: 1'));
    });
  });

  group('EthSignature', () {
    test('equality', () {
      final zero = Felt(Uint8List(32));
      final a = EthSignature(rLow: zero, rHigh: zero, sLow: zero, sHigh: zero, v: zero);
      final b = EthSignature(rLow: zero, rHigh: zero, sLow: zero, sHigh: zero, v: zero);
      expect(a, equals(b));
    });
  });

  // Integration tests — only run when KMS_LIB_PATH is set
  final hasLib = Platform.environment.containsKey('KMS_LIB_PATH');

  group('integration', skip: hasLib ? null : 'KMS_LIB_PATH not set', () {
    late Kms kms;

    setUp(() {
      kms = Kms.instance;
    });

    test('getAbiVersion returns (2, 0)', () {
      final (major, minor) = kms.getAbiVersion();
      expect(major, equals(2));
      expect(minor, equals(0));
    });

    test('getVersionString is non-empty', () {
      final version = kms.getVersionString();
      expect(version.isNotEmpty, isTrue);
    });

    test('felt hex roundtrip via C', () {
      const hex = '0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7';
      final felt = kms.feltFromHex(hex);
      final result = kms.feltToHex(felt);
      expect(result, equals(hex));
    });

    test('felt bytes roundtrip via C', () {
      final original = Felt.fromHex('0xdeadbeef');
      final bytesOut = kms.feltToBytesBe(original);
      final roundtrip = kms.feltFromBytesBe(bytesOut);
      expect(roundtrip, equals(original));
    });

    test('generate and validate mnemonic', () {
      final mnemonic = kms.generateMnemonic(12);
      expect(mnemonic.split(' ').length, equals(12));
      kms.validateMnemonic(mnemonic); // should not throw
    });

    test('validate mnemonic rejects garbage', () {
      expect(
        () => kms.validateMnemonic('not a valid mnemonic phrase'),
        throwsA(isA<KmsException>()),
      );
    });

    test('mnemonic to seed produces 64 bytes', () {
      final mnemonic = kms.generateMnemonic(12);
      final seed = kms.mnemonicToSeed(mnemonic);
      expect(seed.length, equals(64));
    });

    test('derive private key', () {
      final mnemonic = kms.generateMnemonic(12);
      final coinTypes = kms.coinTypes;
      final key = kms.derivePrivateKey(
        mnemonic,
        index: 0,
        accountIndex: 0,
        coinType: coinTypes['tongo']!,
      );
      expect(key.bytes.length, equals(32));
    });

    test('derive keypair', () {
      final mnemonic = kms.generateMnemonic(12);
      final coinTypes = kms.coinTypes;
      final kp = kms.deriveKeypair(
        mnemonic,
        index: 0,
        accountIndex: 0,
        coinType: coinTypes['tongo']!,
      );
      expect(kp.privateKey.bytes.length, equals(32));
    });

    test('pedersen hash', () {
      final a = kms.feltFromHex('0x1');
      final b = kms.feltFromHex('0x2');
      final result = kms.pedersenHash(a, b);
      expect(result.bytes.length, equals(32));
      // Deterministic — same inputs yield same output
      final result2 = kms.pedersenHash(a, b);
      expect(result, equals(result2));
    });

    test('poseidon hash many', () {
      final values = [kms.feltFromHex('0x1'), kms.feltFromHex('0x2')];
      final result = kms.poseidonHashMany(values);
      expect(result.bytes.length, equals(32));
    });

    test('coin types are populated', () {
      final ct = kms.coinTypes;
      expect(ct.containsKey('tongo'), isTrue);
      expect(ct.containsKey('starknet'), isTrue);
      expect(ct.containsKey('nostr'), isTrue);
    });

    test('error name and message', () {
      final name = kms.errorName(-1);
      expect(name.isNotEmpty, isTrue);
      final msg = kms.errorMessage(-1);
      expect(msg.isNotEmpty, isTrue);
    });

    test('derive nostr keypair', () {
      final mnemonic = kms.generateMnemonic(12);
      final kp = kms.deriveNostrKeypair(
        mnemonic,
        index: 0,
        accountIndex: 0,
      );
      expect(kp.privateKey.length, equals(32));
      expect(kp.publicKeyXonly.length, equals(32));
    });

    test('projective <-> affine roundtrip', () {
      final mnemonic = kms.generateMnemonic(12);
      final coinTypes = kms.coinTypes;
      final kp = kms.deriveKeypair(
        mnemonic,
        index: 0,
        accountIndex: 0,
        coinType: coinTypes['tongo']!,
      );
      final affine = kms.projectiveToAffine(kp.publicKey);
      final back = kms.projectiveFromAffine(affine);
      final affine2 = kms.projectiveToAffine(back);
      expect(affine, equals(affine2));
    });
  });
}
