import 'package:flutter_test/flutter_test.dart';
import 'package:bip39_multi/bip39_multi.dart' as bip39;
import 'package:hex/hex.dart';
import 'dart:typed_data';
import 'package:bitcoin_flutter/bitcoin_flutter.dart';
import 'package:flutter/services.dart';

import 'package:digi_password/digi_password.dart';

void main() async {
  //fake some method calls that are only available in app
  const MethodChannel channel = MethodChannel('com.tekartik.sqflite');
  final List<MethodCall> log = <MethodCall>[];
  String response="test";
  channel.setMockMethodCallHandler((MethodCall methodCall) async {
    log.add(methodCall);
    return response;
  });

  //constants
  //define DigiByte Network
  final NetworkType _digibyte = NetworkType(
      messagePrefix: '\x19DigiByte Signed Message:\n',
      bech32: 'dgb',
      bip32: new Bip32Type(public: 0x0488b21e, private: 0x0488ade4),
      pubKeyHash: 0x1e,
      scriptHash: 0x3f,
      wif: 0x80);
  Uint8List seed_expected=Uint8List.fromList([111, 161, 52, 8, 109, 182, 127, 224, 160, 108, 151, 121, 171, 56, 21, 189, 160, 146, 128, 218, 207, 123, 94, 230, 75, 199, 133, 11, 41, 175, 86, 94, 104, 7, 136, 189, 196, 230, 129, 2, 119, 163, 138, 44, 78, 87, 203, 149, 181, 76, 77, 93, 146, 138, 26, 111, 55, 114, 0, 43, 109, 22, 62, 254]);
  String xpub_expected="xpub6DTK2h8fk9xMAaeoAzL2vC9RCki6BarVjgGbqUGjyNpk2wV3pt2kPWSoyfwctobvHJATB8K5KozykDPdrpytDupWi4rWhrx43nyTZURD855";


  //load DigiPassword
  print("Loading DigiPassword.  May take a while.");
  final digiPassword = DigiPassword();
  digiPassword.seed=seed_expected;
  print("loading complete");







  /*
    Standards Test: BIP39 Mnemonic to seed test:
      mnemonic "ask ask ask" has a seed value of
      [111, 161, 52, 8, 109, 182, 127, 224,
       160, 108, 151, 121, 171, 56, 21, 189,
       160, 146, 128, 218, 207, 123, 94, 230,
       75, 199, 133, 11, 41, 175, 86, 94,
       104, 7, 136, 189, 196, 230, 129, 2,
       119, 163, 138, 44, 78, 87, 203, 149,
       181, 76, 77, 93, 146, 138, 26, 111,
       55, 114, 0, 43, 109, 22, 62, 254]

       in hex
       6fa134086db67fe0a06c9779ab3815bda09280dacf7b5ee64bc7850b29af565e680788bdc4e6810277a38a2c4e57cb95b54c4d5d928a1a6f3772002b6d163efe
     */
  test('BIP39 Mnemonic to seed', () async {
    Uint8List seed_calculated = HEX.decode(
        bip39.mnemonicToSeedHex("ask ask ask"));
    expect(seed_calculated, seed_expected,
        reason: "Mnemonic to seed conversion failed");
  });





  /*
    Standard Tests: BIP44 seed to xpub:
      mnemonic "ask ask ask" has a xpub value of "xpub6DTK2h8fk9xMAaeoAzL2vC9RCki6BarVjgGbqUGjyNpk2wV3pt2kPWSoyfwctobvHJATB8K5KozykDPdrpytDupWi4rWhrx43nyTZURD855"
     */

  test('BIP44 seed to xpub', () async {
    String xpub_calculated=HDWallet.fromSeed(seed_expected,network: _digibyte).derivePath("m/44'/20'/0'").base58;
    expect(xpub_calculated,xpub_expected,reason: "Seed to xpub conversion failed");

  });





  /*
    Standard Tests: BIP44 seed to xpub:
      mnemonic "ask ask ask" has a xpub value of "xpub6DTK2h8fk9xMAaeoAzL2vC9RCki6BarVjgGbqUGjyNpk2wV3pt2kPWSoyfwctobvHJATB8K5KozykDPdrpytDupWi4rWhrx43nyTZURD855"
     */




  test('DigiPassword Outputs', () async {
    expect(await digiPassword.password("test"),"Material743License*wait*marble*");
  });

}
