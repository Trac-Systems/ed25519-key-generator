import * as keygen from './index.js';

// TODO: Implement a better test suite

console.log(keygen.generateKeyPair());

const testMnemonic = 'mirror tiger monitor answer blade slot spend chalk arrive pill rich fever'
const testPubKey = Buffer.from("3ceafa43e4936784bd53cb6ef45cfab5637186c3f4f8391bc0f6299df624f38b", 'hex');
console.log(keygen.generateKeyPair(testMnemonic).publicKey.equals(testPubKey)); // true