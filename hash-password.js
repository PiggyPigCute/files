const bcrypt = require('bcryptjs');

const password = process.argv[2];

if (!password) {
  console.error('Usage : node hash-password.js <ton-mot-de-passe>');
  process.exit(1);
}

const hash = bcrypt.hashSync(password, 10);

console.log('\nAjoute cette ligne dans ton fichier .env :\n');
console.log(`PASSWORD_HASH=${hash}\n`);
