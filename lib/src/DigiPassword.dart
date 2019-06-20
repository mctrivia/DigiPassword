import 'package:bitcoin_flutter/bitcoin_flutter.dart';
import 'package:crypto/crypto.dart';
import 'dart:convert';
import 'package:bip39_multi/src/wordlists/english.dart';
import 'package:bs58check/bs58check.dart' as base58;
import 'package:hex/hex.dart';
import 'dart:typed_data';
import 'package:http/http.dart';



class DigiPassword {

/* _____ _             _      _
  / ____(_)           | |    | |
 | (___  _ _ __   __ _| | ___| |_ ___  _ __
  \___ \| | '_ \ / _` | |/ _ \ __/ _ \| '_ \
  ____) | | | | | (_| | |  __/ || (_) | | | |
 |_____/|_|_| |_|\__, |_|\___|\__\___/|_| |_|
                  __/ |
                 |___/
*/
  //setup as a singleton
  static final DigiPassword _singleton = new DigiPassword._internal();
  factory DigiPassword() {
    return _singleton;
  }
  DigiPassword._internal() ;




/* _____                _              _
  / ____|              | |            | |
 | |     ___  _ __  ___| |_ __ _ _ __ | |_ ___
 | |    / _ \| '_ \/ __| __/ _` | '_ \| __/ __|
 | |___| (_) | | | \__ \ || (_| | | | | |_\__ \
  \_____\___/|_| |_|___/\__\__,_|_| |_|\__|___/
*/
  final NetworkType _digibyte = new NetworkType(
      messagePrefix: '\x19DigiByte Signed Message:\n',
      bech32: 'dgb',
      bip32: new Bip32Type(public: 0x0488b21e, private: 0x0488ade4),
      pubKeyHash: 0x1e,
      scriptHash: 0x3f,
      wif: 0x80);
  

/*_____       _ _   _       _ _
 |_   _|     (_) | (_)     | (_)
   | |  _ __  _| |_ _  __ _| |_ _______
   | | | '_ \| | __| |/ _` | | |_  / _ \
  _| |_| | | | | |_| | (_| | | |/ /  __/
 |_____|_| |_|_|\__|_|\__,_|_|_/___\___|
*/

  //allow initialize
  List<int> _salt;
  Map<String,int> _indexs;
  HDWallet _hdWallet;
  set seed(List<int> seed) {
    _hdWallet=HDWallet.fromSeed(seed, network: _digibyte);

    //Version 1.0 doesn't use below.  Included to show values will be needed
    _salt=sha256.convert(seed).bytes;
    _indexs=Map<String,int>();  //place holder should be getting from database

  }

  
/*_____      _            _         ______                _   _
 |  __ \    (_)          | |       |  ____|              | | (_)
 | |__) | __ ___   ____ _| |_ ___  | |__ _   _ _ __   ___| |_ _  ___  _ __  ___
 |  ___/ '__| \ \ / / _` | __/ _ \ |  __| | | | '_ \ / __| __| |/ _ \| '_ \/ __|
 | |   | |  | |\ V / (_| | ||  __/ | |  | |_| | | | | (__| |_| | (_) | | | \__ \
 |_|   |_|  |_| \_/ \__,_|\__\___| |_|   \__,_|_| |_|\___|\__|_|\___/|_| |_|___/
*/
  //Compute domain hash
  List<int> _getHash(String domain) {
    //hash domain and user id
    List<int> bytes = [0, 0, 0, 0];                                             //initialize with 4 bytes of 0
    bytes.addAll(utf8.encode(domain));                                          //add domain to end
    return sha256.convert(bytes).bytes;                                         //take sha256(0x00000000+domain)
  }

  ///To make sure there is no way to link records of hashes to domain we salt the
  ///site hash with salt then hash it again
  String _getIndexHash(List<int> domainHash) {
    final List<int> temp=List<int>.from(_salt);                                 //copy salt to temp
    temp.addAll(domainHash);                                                    //add domainHash to end of salt
    return HEX.encode(sha256.convert(temp).bytes);                              //take sha256(salt+domainHash) and return as hex string
  }

  //Calculate index for given hash
  int _getIndex(List<int> domainHash) {
    return _indexs[_getIndexHash(domainHash)] ?? 0;                             //if no records of site index in database then index is 0
  }

  String _getPath(List<int> domainHash,int mainIndex) {
    String path = "m/$mainIndex'";
    for (int i = 0; i < 16; i += 4) {
      path += "/" +
          ((domainHash[i + 3] & 0x7f) << 24 |
          domainHash[i + 2] << 16 |
          domainHash[i + 1] << 8 |
          domainHash[i]).toString() + "'";
    }
    return path;
  }






/*_____       _     _ _        ______                _   _
 |  __ \     | |   | (_)      |  ____|              | | (_)
 | |__) |   _| |__ | |_  ___  | |__ _   _ _ __   ___| |_ _  ___  _ __  ___
 |  ___/ | | | '_ \| | |/ __| |  __| | | | '_ \ / __| __| |/ _ \| '_ \/ __|
 | |   | |_| | |_) | | | (__  | |  | |_| | | | | (__| |_| | (_) | | | \__ \
 |_|    \__,_|_.__/|_|_|\___| |_|   \__,_|_| |_|\___|\__|_|\___/|_| |_|___/
*/
  ///Password Generator
  ///Generates a 67bit deterministic password for any given value of domain
  String password(String domain) {
    if (_hdWallet==null) throw("DigiPassword not initialized");

    //get initial values
    List<int> hash=_getHash(domain);
    int index=_getIndex(hash);
    String path=_getPath(hash,13)+"/"+index.toString()+"'";

    //calculate sudo random number
    HDWallet hdWallet = _hdWallet.derivePath(path);
    String address = hdWallet.address;
    var rnd = base58.decode(address).sublist(1); //rnd=pubkeyhash which is 20 bytes of sudo random data

    //generate a password based on rand
    List<String> parts = [];
    for (int i = 0; i < 4; i++) {
      int part = rnd[i * 2] * 0x100 + rnd[i * 2 + 1];
      String word = WORDLIST[part % 2048];
      if (part >= 0x8000)
        word = word.substring(0, 1).toUpperCase() +
            word.substring(1); //upper case if msb is 1
      parts.add(word);
      parts.add("");
    }

    //put symbol in remaining places
    String symbol = "!@#\$%^&*-"[rnd[10] % 8];
    for (int i = 1; i < 8; i += 2) {
      parts[i] = symbol;
    }

    //add a 10 bit number in any of the 4 spaces
    int part = rnd[8] * 0x100 + rnd[9];
    int num = part % 1024;
    int loc = (part ~/ 0x4000) * 2 + 1;
    parts[loc] = num.toString();

    //13*4 bits four word parts
    //10 bits for number
    //2 bits for location of number
    //3 bits for symbol
    //total 67
    return parts.join();
  }

  Future<bool> postPassword(String domain,String uri) async {
    if (_hdWallet==null) throw("DigiPassword not initialized");

    //decode uri and validate
    final Map<String,String> params=Uri.parse(uri).queryParameters;
    if (params["s"]==null || params["x"]==null || params["p"]==null) throw("Invalid URI");
    if (params["s"].length<44) throw("OTP key invalid");
    Uint8List key;
    try {
      key=HEX.decode(params["s"]);
    } catch(_) {
      throw("OTP key invalid");
    }
    final String callback="https://${params['p']}";
    final String nonce=params["x"];
    if (nonce.length<10) throw("Invalid nonce");

    //get initial values
    List<int> hash=_getHash(domain);
    int index=_getIndex(hash);
    String path=_getPath(hash,13)+"/"+index.toString()+"'";

    //calculate sudo random number
    HDWallet hdWallet = _hdWallet.derivePath(path);
    String address = hdWallet.address;
    var rnd = base58.decode(address).sublist(1); //rnd=pubkeyhash which is 20 bytes of sudo random data

    //add 2 byte config variable to end of rnd
    int config=3;
    Uint8List payload=Uint8List(22);
    payload.setRange(0, 20, rnd);
    payload.setRange(20,22,[(config/256).floor(),config%256]);  //break each byte of config up and add to rnd

    //encrypt rnd and config
    for (int i=0;i<22;i++) {
      payload[i]^=key[i];
    }

    var client = new Client();
    Response response=await client.post(callback, body: {"x": nonce, "p": HEX.encode(payload)}).timeout(Duration(seconds: 30),onTimeout: () {
      return Response("Timeout",500);//if takes more then 30 seconds fail
    });  //send data to server
    return (response.statusCode==200 || response.statusCode==201);
  }

}