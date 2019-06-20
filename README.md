# digi_password

DigiPassword Library

## About

DigiPassword is an open source protocol based losely on SLIP-0013 allowing for the creation of strong unique passwords for every domain using a single seed phrase.

Any wallet or app is free to implement this standard.  To allow user migration and preventing fracturing of the standard it is vital to confirm the tests in test folder pass in your implementation.

## Getting Started

````
//Create refrence to library
DigiPassword digiPassword=DigiPassword();

//initialise with users seed(512 bit Uint8List) see 
// https://pub.dev/packages/bitcoin_flutter and 
// https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki 
// for more info
Uint8List seed=Uint8List.fromList([111, 161, 52, 8, 109, 182, 127, 224, 160, 108, 151, 121, 171, 56, 21, 189, 160, 146, 128, 218, 207, 123, 94, 230, 75, 199, 133, 11, 41, 175, 86, 94, 104, 7, 136, 189, 196, 230, 129, 2, 119, 163, 138, 44, 78, 87, 203, 149, 181, 76, 77, 93, 146, 138, 26, 111, 55, 114, 0, 43, 109, 22, 62, 254]);
digiPassword.seed=seed;

//To get a password
String domain="user entered domain like google or bank";
String password=await digiPassword.password(domain);

//to transmit a password to a browser plugin 
// for example https://chrome.google.com/webstore/detail/digi-idantumid-easy-exten/bnnpdbkedgbfbmnoihaallekiiaffjhi?hl=en
//String domain="duplicated from above for clarity";
String uri="value provided by browser widget.  Usually encoded in a QR code"
bool passed=false;
try {
  passed = await digiPassword.postPassword(domain, uri);
} catch (_) {}
````