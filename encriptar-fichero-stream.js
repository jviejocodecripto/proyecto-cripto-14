const {createCipheriv, createECDH}  = require("crypto")
const { exit } = require("process")
const args = require("yargs").argv
const fs = require("fs")

if (!args.private && !args.public && !args.data) {
    console.log("faltan parametros");
    exit(0)
}

const origen = createECDH("secp521r1")
const key = fs.readFileSync("./data/" + args.private + ".key").toString()
origen.setPrivateKey(key, "hex")

const pub = fs.readFileSync("./data/" + args.public + ".pb").toString()

// creacion de la clave secreta compartida
const secret = Uint8Array.from(origen.computeSecret(pub, "hex", 'binary'))

// cifrado del fichero
const algo = "aes-256-cbc"
var cifrador = createCipheriv(algo, secret.slice(0, 32), secret.slice(0, 16))

fs.createReadStream("./data/"+ args.data)
   .pipe(cifrador)
   .pipe(new fs.createWriteStream("./data/"+ args.public + "-"+ args.data + ".enc"))

