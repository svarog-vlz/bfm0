const crypto = require('crypto');
const secp256k1 = require('secp256k1');
const fs = require('fs')
const readline = require('readline');
//configs
const algotype = "sha256";
const keyfile = "keys.json"

const rl = readline.createInterface({
		  input: process.stdin,
		  output: process.stdout
	});

//get script arguments
if (process.argv[2] == "newkeys") {
	getNewKeys();
}
let message, sig, publickey;

if (process.argv[2] == "sign") {
	rl.question('Please, paste you message: ', (answer) => {
	   if (answer.length > 1) {
	   		getMessageSign(answer)
			  		
			   }
	});

}



if (process.argv[2] == "verify") {

	
	let message, sig, publickey;
	rl.question('Please, paste message: ', (answer) => {
	   if (answer.length > 1) {
	   		message = answer;
	   		rl.question('Please, paste sig: ', (answer) => {
			   if (answer.length > 1) {
			   		sig = answer;
			   		rl.question('Please, paste public key or push Enter to use previously generated key: ', (answer) => {
					   if (answer.length > 2) {
					   		publickey = answer;
					   		getMessageVeryfy (message, sig, publicKey)
						   } else getMessageVeryfy (message, sig)
						});
			   }
			});
	   }
	});

}


//generetating and write public/privatekey
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
  rl.close();
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
You digital sign: ${sig.toString("hex")}`
				)
			rl.close();
   });
/* end Sign message*/	

}
/*verified message*/
function getMessageVeryfy (message, sig, publicKey = null) {
	//if publicKey is nulled, get this from file
	if (!publicKey) {
		fs.readFile('keys.json', 'utf8', function (err, data) {
   			if (err) throw err;
      		keys = JSON.parse(data);
     		
      		let messagehash = digest(message);
      		//bufered our secret key
      		const public = new Buffer(keys.public, "hex");

      		let verified = secp256k1.verify(messagehash, Buffer(sig, "hex"), public);
			console.log(`Verified: ${verified};`);
   });	
	}
	rl.close();
}


function digest(str, algo = "sha256") {
  return crypto.createHash(algo).update(str).digest();
}

