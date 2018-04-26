const crypto = require('crypto');
const secp256k1 = require('secp256k1');
const fs = require('fs')

//config
const algotype = "sha256";
const keyfile = "keys.json"



//get script arguments
if (process.argv[2] == "newkeys") {
	getNewKeys();
}

if (process.argv[2] == "sign") {
	if (process.argv[3].length>1) {
		getMessageSign(process.argv[3]);
	}
	else console.log(`Comand sign need 1 more argument - stirng`)
}

//generetating and write public/privatekey
function getNewKeys() {
	let privateKey;
	do {
	  privateKey = crypto.randomBytes(32);
	} while (!secp256k1.privateKeyVerify(privateKey));
	// get the public key in a compressed format
	const publicKey = secp256k1.publicKeyCreate(privateKey);
	console.log(privateKey);
	let keys = {
		public: publicKey.toString("hex"),
		private: privateKey.toString("hex") 
	}
	//write keys into keys.json
	fs.writeFile('keys.json', JSON.stringify(keys), (err, fd) => {
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
/*end getNewKeys() */


/*Sign message*/
function getMessageSign(message) {
	
	fs.readFile('keys.json', 'utf8', function (err, data) {
   if (err) throw err;
      keys = JSON.parse(data);
     
      		let messagehash = digest(message);
      		//bufered our secret key
      		const secret = new Buffer(keys.private, "hex");
      		let sigObj = secp256k1.sign(messagehash, secret);
			let sig = sigObj.signature;
			console.log(`You message: ${message};
${algotype} hash: ${messagehash.toString("hex")};
You dugital sign: ${sig.toString("hex")}`
				)
   });
/* end Sign message*/	

}

function digest(str, algo = "sha256") {
  return crypto.createHash(algo).update(str).digest();
}

function utf8Length(s)
{
    var l = 0;
    for (var i = 0; i < s.length; i++) {
        var c = s.charCodeAt(i);
        if (c <= 0x007f) l += 1;
        else if (c <= 0x07ff) l += 2;
        else if (c >= 0xd800 && c <= 0xdfff)  l += 2;  // surrogates
        else l += 3;
    }
    return l;
}