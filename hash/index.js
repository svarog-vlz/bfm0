const crypto = require('crypto');
const secp256k1 = require('secp256k1');
const fs = require('fs')
// or require('secp256k1/elliptic')
//   if you want to use pure js implementation in node

if (process.argv[2] = "newkeys") {
	getNewKeys();
}

function getNewKeys() {
	let privateKey;
	do {
	  privateKey = crypto.randomBytes(32);
	} while (!secp256k1.privateKeyVerify(privateKey));
	// get the public key in a compressed format
	const publicKey = secp256k1.publicKeyCreate(privateKey);
	let keys = {
		public: publicKey.toString("hex"),
		private: privateKey.toString("hex") 
	}
	fs.writeFile('keys.json', JSON.stringify(keys),(err, fd) => {
		  if (err) {
		    if (err.code === 'EEXIST') {
		      console.error('ile already exists');
		      return;
		    }

		    throw err;
		  }
		  console.log(`You new keypair:
	publicKey: ${publicKey.toString("hex")}
	secretKey: ${privateKey.toString("hex")} 
	keys were written to keys.json
	`);
  
});


	
}

function digest(str, algo = "sha256") {
  return crypto.createHash(algo).update(str).digest();
}