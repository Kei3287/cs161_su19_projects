package proj2

// git push -u origin [branch_name]
// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	// You neet to add with
	// go get github.com/nweaver/cs161-p2/userlib

	"github.com/ryanleh/cs161-p2/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"

	// optional
	_ "strconv"
	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg
	// see someUsefulThings() below
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// The structure definition for a user record
type User struct {
	Username         string
	SourceKey        []byte
	HmacKey          []byte
	SymKey           []byte
	UserUUID         uuid.UUID
	RsaSk            userlib.PKEDecKey
	DsSk             userlib.DSSignKey
	SharedFiles      map[string][]byte
	ListOfOwnedFiles map[string]bool // the list of filenames where the user is the original owner of the file
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type UserEntry struct {
	CipherText []byte
	Sigma      []byte
}

type FileEntry struct {
	CipherText       [][]byte // each file entry is a list of encrypted files
	Sigma            []byte
	SigmaSharedUsers []byte
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password

/*InitUser
- Derive sourceKey = Argon2Key(password, username, 16)
- k1 = HMACEval(sourceKey, username)
- k2 = HMACEval(sourceKey, 1 + username)
- Generate public/private keys using PKEKeyGen() and DSKeyGen()

- userUUID = bytesToUUID(HMACEval(k1, username))
- Determine if this UUID is already in the dataStore, if so, return

- Create new User struct
- Populate User with RSA_sk, DS_sk, and map[sharedfileUUID] = k6||k7
- This map[sharedfileUUID, your_version_of_filename] = k6||k7 will be a list of all files for which you have access to but are not an owner
- Pad User
- userEntry = HMACEval(k1, SymEnc(k2, IV, userdata)), SymEnc(k2, IV, userdata)
- datastore[userUUID] = userEntry

- keystore[username||"enc"] = RSA_pk
- keystore[username||"sig"] = DS_pk

- return userdata (is this safe) */
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	sourceKey := userlib.Argon2Key([]byte(password), []byte(username), 16)
	hmacKey, symKey := generateKeysForDataStore(username, sourceKey, []byte(username), []byte(username+"1"))

	// check if username already exists
	filename, _ := userlib.HMACEval(hmacKey, []byte(username))
	userUUID := bytesToUUID(filename)
	if _, ok := userlib.KeystoreGet(username + "enc"); ok {
		// if a user with the same username exists, return an error
		return nil, errors.New("Username already exists")
	}

	// generate RSA encryption keys
	rsaPk, rsaSk, _ := userlib.PKEKeyGen()
	userlib.KeystoreSet(username+"enc", rsaPk)

	// generate RSA signature keys
	dsSk, dsPk, _ := userlib.DSKeyGen()
	userlib.KeystoreSet(username+"sig", dsPk)

	// initialize User struct
	userdataptr.Username = username
	userdataptr.SourceKey = sourceKey
	userdataptr.HmacKey = hmacKey
	userdataptr.SymKey = symKey
	userdataptr.UserUUID = userUUID
	userdataptr.RsaSk = rsaSk
	userdataptr.DsSk = dsSk
	userdataptr.SharedFiles = make(map[string][]byte)
	userdataptr.ListOfOwnedFiles = make(map[string]bool)

	userdataMarshal, _ := json.Marshal(userdata)

	// encrypt and store userdata in the datastore
	var encryptedData UserEntry
	iv := userlib.RandomBytes(16)
	encryptedData.CipherText = userlib.SymEnc(userdataptr.SymKey, iv, padString(userdataMarshal)) // cipherText = iv || c
	encryptedData.Sigma, _ = userlib.HMACEval(userdataptr.HmacKey, encryptedData.CipherText)

	data, _ := json.Marshal(encryptedData)

	fileUUID := bytesToUUID([]byte(filename))
	userlib.DatastoreSet(fileUUID, data)

	return &userdata, nil
}

func generateKeysForDataStore(username string, sourceKey []byte, hmacKeySalt []byte, encKeySalt []byte) ([]byte, []byte) {
	hmacKey, _ := userlib.HMACEval(sourceKey, []byte(hmacKeySalt))
	encKey, _ := userlib.HMACEval(sourceKey, []byte(encKeySalt))
	return hmacKey[0:16], encKey[0:16]
}

func generateFileKeysForDataStore(filename string, username string, sourceKey []byte) ([]byte, []byte, []byte, []byte) {
	fileEncKey, _ := userlib.HMACEval(sourceKey, []byte(filename+username+"enc"))
	fileMacKey, _ := userlib.HMACEval(sourceKey, []byte(filename+username+"sig"))
	sharedfileEncKey, _ := userlib.HMACEval(sourceKey, []byte(filename+username+"shareenc"))
	sharedfileMacKey, _ := userlib.HMACEval(sourceKey, []byte(filename+username+"sharesig"))

	return fileEncKey[0:16], fileMacKey[0:16], sharedfileEncKey[0:16], sharedfileMacKey[0:16]
}

// pad with 0 and the last byte contains how many bytes of padding needed
// padding reference : https://sourcegraph.com/github.com/apexskier/cryptoPadding/-/blob/ansix923.go#L17
func padString(str []byte) []byte {
	var padBytes int
	if len(str)%userlib.AESBlockSize == 0 {
		padBytes = userlib.AESBlockSize
	} else {
		padBytes = userlib.AESBlockSize - (len(str) % userlib.AESBlockSize)
	}
	padText := []byte(strings.Repeat(string([]byte{byte(0)}), padBytes-1))
	str = append(str, append(padText, byte(padBytes))...)
	return str
}

// TODO: add error checking
func unpadString(str []byte) []byte {
	padBytes := int(str[len(str)-1])
	return str[0 : len(str)-padBytes]
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.

/*GetUser
- Derive sourceKey = Argon2Key(password, username, 16)
- k1 = HMACEval(sourceKey, username)
- k2 = HMACEval(sourceKey, 1 + username)
- userUUID = bytesToUUID(HMACEval(k1, username))

- Check if userUUID is in the datastore. If not, return error
- a userUUID won't exist if the username or password is wrong
- get the userEntry at userUUID
- Take HMACEval(k1, SymEnc(k2, IV, userdata)) and verify this with userEntry
- If not equal, return error
*/
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	sourceKey := userlib.Argon2Key([]byte(password), []byte(username), 16)
	hmacKey, symKey := generateKeysForDataStore(username, sourceKey, []byte(username), []byte(username+"1"))
	filename, _ := userlib.HMACEval(hmacKey[0:16], []byte(username))
	userUUID := bytesToUUID(filename)
	marshalData, ok := userlib.DatastoreGet(userUUID)
	_, usernameOk := userlib.KeystoreGet(username + "enc")
	if !ok || !usernameOk {
		return nil, errors.New("The username doesn't exist or wrong password")
	}
	var data UserEntry
	json.Unmarshal(marshalData, &data)

	signature, _ := userlib.HMACEval(hmacKey, data.CipherText)
	if !userlib.HMACEqual(signature, data.Sigma) {
		return nil, errors.New("data corrupted")
	}
	decryptedData := userlib.SymDec(symKey, data.CipherText)
	userdataMarshal := unpadString(decryptedData)
	json.Unmarshal(userdataMarshal, userdataptr)
	return userdataptr, nil
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
// edge case, storing a file that's already stored

/*StoreFile
- Obtain username from userdata
- Derive sourceKey = Argon2Key(password, username, 16)  (how can the user find the password in the implementation?)
- k3 = HMACEval(sourceKey, filename + username + "enc")
- k4 = HMACEval(sourceKey, filename + username + "sig")
- k6 = HMACEval(sourceKey, filename + username + "shareEnc")
- k7 = HMACEval(sourceKey, filename + username + "shareSig")
- fileUUID = bytesToUUID(HMAC(k3, filename))
- sharedfileUUID = bytesToUUID(HMAC(k6, k7))

- Check if fileUUID or sharedfileUUID already exists in datastore. If so, return (*or replace old file contents)

- create fileData struct
- populate fileData with signature, ciphertext, and list_of_shared_people
- ciphertext = SymEnc(k3, IV, list(data))
- list_of_shared_people = list(userUUID of owner)  (when you first store a file, you are the only person who can access)
- signature = HMACEval(k4, ciphertext)

- store datastore[fileUUID] = HMACEval(k4, SymEnc(k3, IV, fileData))
*/
func (userdata *User) StoreFile(filename string, data []byte) {
	// no one can store file when they do not exist in the datastore & keystore
	_, dataStoreOk := userlib.DatastoreGet(userdata.UserUUID)
	_, keyStoreOk := userlib.KeystoreGet(userdata.Username + "enc")
	if !dataStoreOk || !keyStoreOk {
		return
	}

	fileEncKey, fileMacKey, sharedfileEncKey, sharedfileMacKey := generateFileKeysForDataStore(filename, userdata.Username, userdata.SourceKey)

	// sharedFile keys should be taken from userdata struct if exists
	if _, ok := userdata.SharedFiles[filename]; ok {
		sharedfileMacKey = userdata.SharedFiles[filename][0:16]
		sharedfileEncKey = userdata.SharedFiles[filename][16:32]
		hashedSharedFilename, _ := userlib.HMACEval(sharedfileMacKey, []byte("magic_string"))
		sharedfileUUID := bytesToUUID(hashedSharedFilename)
		_, sharedfileOk := userlib.DatastoreGet(sharedfileUUID)
		if sharedfileOk {
			storeData(sharedfileEncKey, data, sharedfileMacKey, hashedSharedFilename, userdata.Username)
			return
		}
	}

	// filling in the FileEntry
	hashedFilename, _ := userlib.HMACEval(fileMacKey, []byte(filename))
	storeData(fileEncKey, data, fileMacKey, hashedFilename, userdata.Username)
	userdata.ListOfOwnedFiles[filename] = true
}

func storeData(fileEncKey []byte, data []byte, fileMacKey []byte, hashedFilename []byte, username string) {
	var encryptedData FileEntry
	fileUUID := bytesToUUID(hashedFilename)
	iv := userlib.RandomBytes(16)
	encryptedData.CipherText = append(encryptedData.CipherText, userlib.SymEnc(fileEncKey, iv, padString(data)))
	// list of encrypted filedata
	ciphertextMarshal, _ := json.Marshal(encryptedData.CipherText)
	// marshalling so I can pass this into sigma
	encryptedData.Sigma, _ = userlib.HMACEval(fileMacKey, []byte(ciphertextMarshal))
	encryptedDataMarshal, _ := json.Marshal(encryptedData)
	userlib.DatastoreSet(fileUUID, encryptedDataMarshal)
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

/*AppendFile
- Find fileUUID for filename in datastore (return error if not found)
- Validate fileEntry for integrity
- Add the new encrypted data to the list of ciphertexts and recompute the HMAC signature
*/
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	// no one can append file when they do not exist in the datastore & keystore
	_, dataStoreOk := userlib.DatastoreGet(userdata.UserUUID)
	_, keyStoreOk := userlib.KeystoreGet(userdata.Username + "enc")
	if !dataStoreOk || !keyStoreOk {
		return errors.New("Cannot append when you don't exist")
	}

	// generating all the necessary keys. If we store them in userdata later, we can just fetch them from userdata
	fileEncKey, fileMacKey, sharedfileEncKey, sharedfileMacKey := generateFileKeysForDataStore(filename, userdata.Username, userdata.SourceKey)

	if _, ok := userdata.SharedFiles[filename]; ok {
		sharedfileMacKey = userdata.SharedFiles[filename][0:16]
		sharedfileEncKey = userdata.SharedFiles[filename][16:32]
		// creating the sharedfileUUID to see if it exists in the datastore already
		encryptedSharedFilename, _ := userlib.HMACEval(sharedfileMacKey, []byte("magic_string"))
		sharedfileUUID := bytesToUUID(encryptedSharedFilename)
		sharedfileMarshal, sharedfileOk := userlib.DatastoreGet(sharedfileUUID)
		if sharedfileOk {
			err := appendData(sharedfileMacKey, sharedfileEncKey, sharedfileMarshal, data, sharedfileUUID)
			return err
		}
	}

	// creating the fileUUID to see if it exists in the datastore already
	encryptedFilename, _ := userlib.HMACEval(fileMacKey, []byte(filename))
	fileUUID := bytesToUUID(encryptedFilename)
	fileMarshal, fileOk := userlib.DatastoreGet(fileUUID)
	if !fileOk {
		return errors.New("Can't append, file requested not in datastore")
	}

	// depending on if the file we want to append to is shared or not, we use different keys
	err = appendData(fileMacKey, fileEncKey, fileMarshal, data, fileUUID)
	return err
}

func appendData(macKeytoUse []byte, encKeytoUse []byte, fileMarshalToUse []byte, data []byte, fileUUID uuid.UUID) error {
	var filedata FileEntry
	json.Unmarshal(fileMarshalToUse, &filedata)

	// checking integrity of ciphertext
	cipherTextMarshal, _ := json.Marshal(filedata.CipherText)
	signature, _ := userlib.HMACEval(macKeytoUse, cipherTextMarshal)
	if !userlib.HMACEqual(signature, filedata.Sigma) {
		return errors.New("file data corrupted") // should we remove these entries from the datastore if they are corrupted?
	}

	// encrypt data and append new encrypted data to the cyphertext list
	iv := userlib.RandomBytes(16)
	filedata.CipherText = append(filedata.CipherText, userlib.SymEnc(encKeytoUse, iv, padString(data)))
	ciphertextMarshal, _ := json.Marshal(filedata.CipherText)                    // marshalling so I can pass this into sigma
	filedata.Sigma, _ = userlib.HMACEval(macKeytoUse, []byte(ciphertextMarshal)) // update sigma on the filedata

	encryptedDataMarshal, _ := json.Marshal(filedata)
	userlib.DatastoreSet(fileUUID, encryptedDataMarshal)
	return nil
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.

/*LoadFile
- calculate fileUUID from filename
- return error if fileUUID not in datastore
- we use different keys depending on if we're loading a shared or not-shared file
- check integrity of file
- decrypt
*/
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	// no one can load file when they do not exist in the datastore & keystore
	_, dataStoreOk := userlib.DatastoreGet(userdata.UserUUID)
	_, keyStoreOk := userlib.KeystoreGet(userdata.Username + "enc")
	if !dataStoreOk || !keyStoreOk {
		return nil, errors.New("Cannot load when you don't exist")
	}

	// generating all the necessary keys. If we store them in userdata later, we can just fetch them from userdata
	fileEncKey, fileMacKey, sharedfileEncKey, sharedfileMacKey := generateFileKeysForDataStore(filename, userdata.Username, userdata.SourceKey)

	if _, ok := userdata.SharedFiles[filename]; ok {
		sharedfileMacKey = userdata.SharedFiles[filename][0:16]
		sharedfileEncKey = userdata.SharedFiles[filename][16:32]
		// creating the sharedfileUUID to see if it exists in the datastore already
		encryptedSharedFilename, _ := userlib.HMACEval(sharedfileMacKey, []byte("magic_string"))
		sharedfileUUID := bytesToUUID(encryptedSharedFilename)
		sharedfileMarshal, sharedfileOk := userlib.DatastoreGet(sharedfileUUID)
		if sharedfileOk {
			decryptedFileData, err := loadData(sharedfileMacKey, sharedfileEncKey, sharedfileMarshal)
			return decryptedFileData, err
		}
	}

	// creating the fileUUID to see if it exists in the datastore already
	encryptedFilename, _ := userlib.HMACEval(fileMacKey, []byte(filename))
	fileUUID := bytesToUUID(encryptedFilename)
	fileMarshal, fileOk := userlib.DatastoreGet(fileUUID)
	if !fileOk {
		return nil, errors.New("Your requested file isn't in the DataStore")
	}

	decryptedFileData, err := loadData(fileMacKey, fileEncKey, fileMarshal)
	return decryptedFileData, err
}

func loadData(macKeytoUse []byte, encKeytoUse []byte, fileMarshalToUse []byte) (data []byte, err error) {
	var filedata FileEntry
	json.Unmarshal(fileMarshalToUse, &filedata)

	// checking integrity of ciphertext
	cipherTextMarshal, _ := json.Marshal(filedata.CipherText)
	signature, _ := userlib.HMACEval(macKeytoUse, cipherTextMarshal)
	if !userlib.HMACEqual(signature, filedata.Sigma) {
		return nil, errors.New("file data corrupted") // TODO: should we remove these entries from the datastore if they are corrupted?
	}

	// decrypts each element in the list, and creates a new concatenated filedata to return
	var decryptedFileData []byte
	for _, slice := range filedata.CipherText {
		decryptedSlice := userlib.SymDec(encKeytoUse, slice)
		decryptedFileData = append(decryptedFileData, decryptedSlice...)
		decryptedFileData = unpadString(decryptedFileData)
	}
	return decryptedFileData, nil
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
	CipherText []byte
	Sigma      []byte
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

/*ShareFile
- See if filename = your_version_of_filename in map[sharedfileUUID, your_version_of_filename] in userdata
- If so, you are trying to share a file for which you are not the owner
	- create magic_string = DSSign(sender's private key, PKEEnc(recipient's public key, k6||k7))

- If not,
- Obtain username from userdata
- Derive sourceKey = Argon2Key(password, username, 16)  (how can the user find the password in the implementation?)
- k3 = HMACEval(sourceKey, filename + username + "enc")
- k4 = HMACEval(sourceKey, filename + username + "sig")
- k6 = HMACEval(sourceKey, filename + username + "shareEnc")
- k7 = HMACEval(sourceKey, filename + username + "shareSig")
- magic_string = DSSign(sender's private key, PKEEnc(recipient's public key, k6||k7))
- fileUUID = bytesToUUID(HMAC(k4, filename))
- sharedfileUUID = bytesToUUID(HMAC(k6, k7))

- Find fileUUID in datastore
- If fileUUID doesn't exist, return
- If fileUUID exists, verify & decrypt the filedata and encrypt/HMAC it again with k6 & k7
- delete fileUUID from datastore

- Later, if Bob calls receiveFile, he will verify & decrypt magic_string, and use k6, k7 to calculate the sharedfileUUID
*/
func (userdata *User) ShareFile(filename string, recipient string) (magic_string string, err error) {
	// no one can share file when they do not exist in the datastore & keystore
	_, dataStoreOk := userlib.DatastoreGet(userdata.UserUUID)
	_, keyStoreOk := userlib.KeystoreGet(userdata.Username + "enc")
	if !dataStoreOk || !keyStoreOk {
		return "", errors.New("Cannot share when you don't exist")
	}

	recipientPk, ok := userlib.KeystoreGet(recipient + "enc")
	if !ok {
		return "", errors.New("invalid recipient")
	}

	var sharingEntry sharingRecord
	var sharedfileMacKey []byte
	var sharedfileEncKey []byte
	keys, isShared := userdata.SharedFiles[filename]
	if isShared {
		// if the file has been shared with somebody before, we simply share the symmetric keys
		sharedfileMacKey = keys[0:16]
		sharedfileEncKey = keys[16:32]
		hashedFilename, _ := userlib.HMACEval(sharedfileMacKey, []byte("magic_string"))
		sharedFileUUID := bytesToUUID(hashedFilename)
		if _, ok := userlib.DatastoreGet(sharedFileUUID); !ok {
			// if the file was revoked or an attacker deleted the file, we can't share the file
			return "", errors.New("File deleted.")
		}
		// initialize sharing
		keys = append(sharedfileMacKey, sharedfileEncKey...)
		sharingEntry.CipherText, _ = userlib.PKEEnc(recipientPk, keys)
		sharingEntry.Sigma, _ = userlib.DSSign(userdata.DsSk, sharingEntry.CipherText)
		sharingEntryMarshal, _ := json.Marshal(sharingEntry)
		return string(sharingEntryMarshal), nil
	}
	// if the file has never been shared before, it means the user if the owner of the file

	// retrieve the original data & delete the original entry
	originalData, error := userdata.LoadFile(filename)
	if error != nil {
		return "", errors.New("Data failed to load.")
	}
	deleteDataEntry(userdata.SourceKey, userdata.Username, filename, []byte(filename+userdata.Username+"sig"), []byte(filename+userdata.Username+"enc"))

	// create new shared symmetric keys
	_, _, sharedfileEncKey, sharedfileMacKey = generateFileKeysForDataStore(filename, userdata.Username, userdata.SourceKey)
	userdata.SharedFiles[filename] = append(sharedfileMacKey, sharedfileEncKey...)
	hashedFilename, _ := userlib.HMACEval(sharedfileMacKey, []byte("magic_string"))

	// store the original data into a new entry shared with the recipient
	storeData(sharedfileEncKey, originalData, sharedfileMacKey, hashedFilename, userdata.Username)

	// initialize sharing
	keys = append(sharedfileMacKey, sharedfileEncKey...)
	sharingEntry.CipherText, _ = userlib.PKEEnc(recipientPk, keys)
	sharingEntry.Sigma, _ = userlib.DSSign(userdata.DsSk, sharingEntry.CipherText)
	sharingEntryMarshal, _ := json.Marshal(sharingEntry)
	return string(sharingEntryMarshal), nil
}

func deleteDataEntry(sourceKey []byte, username string, filename string, hmacSalt []byte, encSalt []byte) {
	fileMacKey, _ := generateKeysForDataStore(username, sourceKey, hmacSalt, encSalt)
	encryptedFilename, _ := userlib.HMACEval(fileMacKey, []byte(filename))
	fileUUID := bytesToUUID(encryptedFilename)
	userlib.DatastoreDelete(fileUUID)
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string, magic_string string) error {
	// no one can receive file when they do not exist in the datastore & keystore
	_, dataStoreOk := userlib.DatastoreGet(userdata.UserUUID)
	_, keyStoreOk := userlib.KeystoreGet(userdata.Username + "enc")
	if !dataStoreOk || !keyStoreOk {
		return errors.New("Cannot receive when you don't exist")
	}

	if _, ok := userdata.SharedFiles[filename]; ok {
		return errors.New("File already shared with someone")
	}

	senderDsPk, ok := userlib.KeystoreGet(sender + "sig")
	if !ok {
		return errors.New("invalid sender")
	}
	var sharingEntry sharingRecord
	json.Unmarshal([]byte(magic_string), &sharingEntry)
	err := userlib.DSVerify(senderDsPk, sharingEntry.CipherText, sharingEntry.Sigma)
	if err != nil {
		return err
	}
	keys, err := userlib.PKEDec(userdata.RsaSk, sharingEntry.CipherText)
	if err != nil {
		return err
	}
	userdata.SharedFiles[filename] = keys
	return nil
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
	// no one can revoke file when they do not exist in the datastore & keystore
	_, dataStoreOk := userlib.DatastoreGet(userdata.UserUUID)
	_, keyStoreOk := userlib.KeystoreGet(userdata.Username + "enc")
	if !dataStoreOk || !keyStoreOk {
		return errors.New("Cannot revoke when you don't exist")
	}

	_, ok := userdata.ListOfOwnedFiles[filename]
	if !ok {
		return errors.New("You have to be the owner of the file to revoke")
	}
	fileEncKey, fileMacKey, _, _ := generateFileKeysForDataStore(filename, userdata.Username, userdata.SourceKey)
	originalData, err := userdata.LoadFile(filename)
	if err != nil {
		return errors.New("Data failed to load.")
	}
	deleteDataEntry(userdata.SourceKey, userdata.Username, "magic_string", []byte(filename+userdata.Username+"sharesig"), []byte(filename+userdata.Username+"shareenc"))
	delete(userdata.SharedFiles, filename)
	hashedFilename, _ := userlib.HMACEval(fileMacKey, []byte(filename))
	storeData(fileEncKey, originalData, fileMacKey, hashedFilename, userdata.Username)
	return nil
}
