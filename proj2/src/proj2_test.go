package proj2

import (
	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/google/uuid"
	"github.com/ryanleh/cs161-p2/userlib"
)

// when running go test -v, make sure to use unique username throught the test file

func TestInit(t *testing.T) {
	t.Log("Initialization test")

	// You may want to turn it off someday
	//userlib.SetDebugStatus(true)
	// someUsefulThings()  //  Don't call someUsefulThings() in the autograder in case a student removes it
	// userlib.SetDebugStatus(false)
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}

func TestInitError(t *testing.T) {
	t.Log("Initialization test")
	//userlib.SetDebugStatus(true)
	u, err := InitUser("alice2", "p")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u, err = InitUser("alice2", "p")
	if err == nil {
		t.Error("Failed to initialize user", err)
		return
	}

	t.Log("should return nil")
	t.Log("Got user", u)
}

/*
func TestGetUser(t *testing.T) {
	t.Log("getUser test")
	userlib.SetDebugStatus(true)
	username := "alice3"
	password := "pass"
	u, err := InitUser(username, password)
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u, err = GetUser(username, password)
	if err != nil {
		t.Error(err)
		return
	}
	t.Log("Got user", u)


		_, _, userUUID := generateKeyAndUUID(username, password)
		if u.Username != username || u.UserUUID != userUUID {
			t.Error("data doesn't match")
			return
		}
}*/

func TestGetUserError(t *testing.T) {
	t.Log("getUserError test")
	//userlib.SetDebugStatus(true)
	username := "alice4"
	password := "pass"
	u, err := InitUser(username, password)
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u, err = GetUser("a", password)
	if err == nil {
		t.Error("failed to get an error")
		return
	}
	u, err = GetUser(username, "fake password")
	if err == nil {
		t.Error("failed to get an error")
		return
	}

	t.Log("should return nil")
	t.Log("Got user", u)
}

func generateKeyAndUUID(username string, password string) (hmacKey []byte, symKey []byte, userUUID uuid.UUID) {
	sourceKey := userlib.Argon2Key([]byte(password), []byte(username), 16)
	hmacKey, _ = userlib.HMACEval(sourceKey, []byte(username))
	symKey, _ = userlib.HMACEval(sourceKey, []byte(username+"1"))
	filename, _ := userlib.HMACEval(hmacKey[0:16], []byte(username))

	// bytestouuid
	for x := range userUUID {
		userUUID[x] = filename[x]
	}
	return hmacKey, symKey, userUUID
}

func TestGetUserAttack(t *testing.T) {
	t.Log("getUserAttack test")
	//userlib.SetDebugStatus(true)
	username5 := "alice5"
	username6 := "alice6"
	username7 := "alice7"
	username8 := "alice8"
	password := "pass"
	u, err := InitUser(username5, password)
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, _, userUUID := generateKeyAndUUID(username5, password)

	// datastore delete entry attack
	userlib.DatastoreDelete(userUUID)
	u, err = GetUser(username5, password)
	if err == nil {
		t.Error("failed to detect the corruption of data")
		return
	}

	// keystore clear attack
	u, err = InitUser(username6, password)
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	userlib.KeystoreClear()
	u, err = GetUser(username6, password)
	if err == nil {
		t.Error("failed to detect the corruption of data")
		return
	}

	// modify the data on datastore attack
	u, err = InitUser(username7, password)
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u, err = InitUser(username8, password)
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	_, _, userUUID7 := generateKeyAndUUID(username7, password)
	_, _, userUUID8 := generateKeyAndUUID(username8, password)
	val, _ := userlib.DatastoreGet(userUUID7)
	userlib.DatastoreSet(userUUID8, val)
	u, err = GetUser(username8, password)
	if err == nil {
		t.Error("failed to detect the corruption of data")
		return
	}

	t.Log("should return nil")
	t.Log("Got user", u)
}

/*
func TestStore(t *testing.T) {
	t.Log("Testing StoreFile")
	userlib.SetDebugStatus(true)

	alice0001, err := InitUser("alice0001", "alice_password")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user alice0001", err)
		return
	}

	alice0001.StoreFile("file_x", []byte("My name is Barry Allen and I am the Flash"))
	alice0001.StoreFile("file_x", []byte("I am Flash"))

	alice0001.StoreFile("file_y", []byte("My name is Barry Allen and I am the Flash"))
	alice0001.StoreFile("file_z", []byte("I'm still the Flash"))

	bob0001, err := InitUser("bob0001", "bob_password")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user bob0001", err)
		return
	}

	bob0001.StoreFile("file_x", []byte("Alice think's she's the Flash, but she's not"))
	bob0001.StoreFile("file_a", []byte("I am the Flash"))

	aliceFilexEnckey, _ := userlib.HMACEval(alice0001.SourceKey, []byte("file_x"+alice0001.Username+"enc"))
	aliceFilexEnc, _ := userlib.HMACEval(aliceFilexEnckey[0:16], []byte("file_x"))
	aliceFilexUUID := bytesToUUID(aliceFilexEnc)

	aliceFileyEnckey, _ := userlib.HMACEval(alice0001.SourceKey, []byte("file_y"+alice0001.Username+"enc"))
	aliceFileyEnc, _ := userlib.HMACEval(aliceFileyEnckey[0:16], []byte("file_y"))
	aliceFileyUUID := bytesToUUID(aliceFileyEnc)

	aliceFilezEnckey, _ := userlib.HMACEval(alice0001.SourceKey, []byte("file_z"+alice0001.Username+"enc"))
	aliceFilezEnc, _ := userlib.HMACEval(aliceFilezEnckey[0:16], []byte("file_z"))
	aliceFilezUUID := bytesToUUID(aliceFilezEnc)

	bobFilexEnckey, _ := userlib.HMACEval(bob0001.SourceKey, []byte("file_x"+bob0001.Username+"enc"))
	bobFilexEnc, _ := userlib.HMACEval(bobFilexEnckey[0:16], []byte("file_x"))
	bobFilexUUID := bytesToUUID(bobFilexEnc)

	bobFileaEnckey, _ := userlib.HMACEval(bob0001.SourceKey, []byte("file_a"+bob0001.Username+"enc"))
	bobFileaEnc, _ := userlib.HMACEval(bobFileaEnckey[0:16], []byte("file_a"))
	bobFileaUUID := bytesToUUID(bobFileaEnc)

	alice0001Enc, _ := userlib.HMACEval(alice0001.HmacKey[0:16], []byte(alice0001.Username))
	alice0001UUID := bytesToUUID(alice0001Enc)

	bob0001Enc, _ := userlib.HMACEval(bob0001.HmacKey[0:16], []byte(bob0001.Username))
	bob0001UUID := bytesToUUID(bob0001Enc)

	entireDatastore := userlib.DatastoreGetMap()

	datastoreKeys := make([]userlib.UUID, len(entireDatastore))
	i := 0
	for k := range entireDatastore {
		datastoreKeys[i] = k
		i++
	}

	localDatastoreKeys := []userlib.UUID{aliceFilexUUID, aliceFileyUUID, aliceFilezUUID, bobFilexUUID, bobFileaUUID, alice0001UUID, bob0001UUID}

	if reflect.DeepEqual(localDatastoreKeys, datastoreKeys) {
		t.Error("datastore keys not correct")
		return
	}
}
*/

func TestLoadFile(t *testing.T) {
	t.Log("Testing LoadFile")
	userlib.SetDebugStatus(true)

	alice0002, err := InitUser("alice0002", "alice_password")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user alice0002", err)
		return
	}

	bob0002, err := InitUser("bob0002", "bob_password")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user bob0002", err)
		return
	}

	alice0002.StoreFile("file1", []byte("pizza does not belong on pepperoni"))
	alice0002.StoreFile("file2", []byte("Bob, I think the government is onto me."))

	alicefile1, _ := alice0002.LoadFile("file1")
	if !reflect.DeepEqual(alicefile1, []byte("pizza does not belong on pepperoni")) {
		t.Error("alicefile1 contents incorrect")
		return
	}

	alicefile2, _ := alice0002.LoadFile("file2")
	if !reflect.DeepEqual(alicefile2, []byte("Bob, I think the government is onto me.")) {
		t.Error("alicefile2 contents incorrect")
		return
	}

	alice0002.StoreFile("file1", []byte("I have updated file1"))

	alicefile1, _ = alice0002.LoadFile("file1")
	if !reflect.DeepEqual(alicefile1, []byte("I have updated file1")) {
		t.Error("alicefile1 contents incorrect") // This implementation assumes calling StoreFile on an existing filename doesn't update it. Debatable
		return
	}

	bob0002.StoreFile("file1", []byte("I like to make my filenames the same name as Alice's filenames to troll her"))

	bobfile1, _ := bob0002.LoadFile("file1")
	if !reflect.DeepEqual(bobfile1, []byte("I like to make my filenames the same name as Alice's filenames to troll her")) {
		t.Error("bobfile1 contents incorrect")
		return
	}

	bob0002.StoreFile("Bob's Favorite File", []byte("I have been tracked down by Dr. Phil and must retreat back into the woods"))

	bobfilefavorite, _ := bob0002.LoadFile("Bob's Favorite File")
	if !reflect.DeepEqual(bobfilefavorite, []byte("I have been tracked down by Dr. Phil and must retreat back into the woods")) {
		t.Error("bobfile1 contents incorrect")
		return
	}
}

func TestAppendFile(t *testing.T) {
	t.Log("Testing AppendFile")
	userlib.SetDebugStatus(true)

	alice0003, err := InitUser("alice0003", "alice_password")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user alice0003", err)
		return
	}

	bob0003, err := InitUser("bob0003", "bob_password")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user bob0003", err)
		return
	}

	alice0003.StoreFile("file1", []byte("Hello. I am Alic"))
	alice0003.AppendFile("file1", []byte("e."))
	alicefile1, _ := alice0003.LoadFile("file1")

	if !reflect.DeepEqual(alicefile1, []byte("Hello. I am Alice.")) {
		t.Error("alicefile1 contents incorrect")
		return
	}

	// Useful to do another test for storefile file1 and load it back again.
	// That will be needed if we change the implementation so that storing a file with the same name updates it instead of return nil

	err = bob0003.AppendFile("file1", []byte("I am a rebel. I append things to files that don't even exist"))
	if err == nil {
		t.Error("failed to catch error: appending file to non-existing file is supposed to error")
	}

	bob0003.StoreFile("file1", []byte("Okay, okay proj2 testers. I will create a file1 that actually exists."))
	bob0003.AppendFile("file1", []byte("...adding more dots bc I'm salty"))
	bobfile1, _ := bob0003.LoadFile("file1")

	if !reflect.DeepEqual(bobfile1, []byte("Okay, okay proj2 testers. I will create a file1 that actually exists....adding more dots bc I'm salty")) {
		t.Error("bobfile1 contents incorrect")
		return
	}

	// Appending to this file again
	bob0003.AppendFile("file1", []byte("hi"))
	bobfile1, _ = bob0003.LoadFile("file1")

	if !reflect.DeepEqual(bobfile1, []byte("Okay, okay proj2 testers. I will create a file1 that actually exists....adding more dots bc I'm saltyhi")) {
		t.Error("bobfile1 contents incorrect")
		return
	}
}

func TestStorage(t *testing.T) {
	u, err := InitUser("alice11", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u, err = GetUser("alice11", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("Loaded user", u)

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

func TestShare(t *testing.T) {
	u, err := InitUser("alice12", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	u, err = GetUser("alice12", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	u.StoreFile("file1", []byte("pizza does not belong on pepperoni"))
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	var v, v2 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice12", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

}

func TestRevoke(t *testing.T) {
	u, err := InitUser("alice13", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	u.StoreFile("file001", []byte("pizza does not belong on pepperoni"))
	u2, err2 := InitUser("bob2", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	var v, v2 []byte
	var magic_string string

	v, err = u.LoadFile("file001")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u.ShareFile("file001", "bob2")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file002", "alice13", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	err = u.RevokeFile("file001")
	if err != nil {
		t.Error("Failed to revoke the file")
	}

	v, err = u.LoadFile("file001")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	if !reflect.DeepEqual(v, []byte("pizza does not belong on pepperoni")) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

	v2, err = u2.LoadFile("file002")
	if err == nil {
		t.Error("Failed to catch an error", err)
		return
	}
	err2 = u2.ReceiveFile("file002", "alice13", magic_string)
	v2, err2 = u2.LoadFile("file002")
	if err2 == nil {
		t.Error("Failed to catch an error", err)
		return
	}
	t.Log("should return nil")
}

func TestAppendShare(t *testing.T) {
	alice0005, err := InitUser("alice0005", "alice_password")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user alice0005", err)
		return
	}

	bob0005, err := InitUser("bob0005", "bob_password")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user bob0005", err)
		return
	}

	alice0005.StoreFile("file1", []byte("hi"))
	magic_string, err := alice0005.ShareFile("file1", "bob0005")
	bob0005.ReceiveFile("file1", "alice0005", magic_string)
	file1, err := bob0005.LoadFile("file1")

	if !reflect.DeepEqual(file1, []byte("hi")) {
		t.Error("file contents wrong when load")
	}

	err = alice0005.AppendFile("file1", []byte("aa"))
	if err != nil {
		t.Error("appendfile error", err)
		return
	}
	file1, err = alice0005.LoadFile("file1")
	if err != nil {
		t.Error("loadfile error", err)
		return
	}
	if !reflect.DeepEqual(file1, []byte("hiaa")) {
		t.Error("file contents wrong when Alice append 1")
	}
	file1, err = bob0005.LoadFile("file1")
	if err != nil {
		t.Error("loadfile error", err)
		return
	}
	if !reflect.DeepEqual(file1, []byte("hiaa")) {
		t.Error("file contents wrong when Alice append 2")
	}

	bob0005.AppendFile("file1", []byte("bb"))
	if err != nil {
		t.Error("appendfile error", err)
		return
	}
	file1, err = alice0005.LoadFile("file1")
	if err != nil {
		t.Error("loadfile error", err)
		return
	}
	if !reflect.DeepEqual(file1, []byte("hiaabb")) {
		t.Error("file contents wrong when Bob append 1")
	}
	file1, err = bob0005.LoadFile("file1")
	if err != nil {
		t.Error("loadfile error", err)
		return
	}
	if !reflect.DeepEqual(file1, []byte("hiaabb")) {
		t.Error("file contents wrong when Bob append 2")
	}
}

func TestCombineShareLoadRevoke(t *testing.T) {
	alice0004, err := InitUser("alice0004", "alice_password")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user alice0004", err)
		return
	}

	bob0004, err := InitUser("bob0004", "bob_password")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user bob0004", err)
		return
	}

	// Alice shares a file that doesn't exist, to Bob
	magic_string_fail, err := alice0004.ShareFile("nonexistingfile", "bob0004")
	if err == nil {
		t.Error("Sharing a nonexisting file to someone should error")
	}

	// Bob attempts to receive the file that doesn't exist that was shared to him
	err = bob0004.ReceiveFile("nonexistingfile", "alice0004", magic_string_fail)
	if err == nil {
		t.Error("Receiving a nonexisting file should fail")
	}

	// Alice creates file1 and file2
	alice0004.StoreFile("file1", []byte("I like pie"))
	alice0004.StoreFile("file2", []byte("Trip to Russia"))

	// Alice shares file1 to a nonexisting person Carol
	magic_string_fail, err = alice0004.ShareFile("file1", "carol0004")
	if err == nil {
		t.Error("Sharing a file with a nonexisting person should fail")
	}

	// Initialize Carol
	carol0004, err := InitUser("carol0004", "carol_password")
	if err != nil {
		t.Error("Failed to initialize user carol0004", err)
		return
	}

	// Carol attempts to receive file1 from Alice. File1 was shared before Carol was initialized
	carol0004.ReceiveFile("file1", "alice0004", magic_string_fail)
	/*
		if err == nil {
			t.Error("You cannot receive a file that was not sent to you when you did not exist yet")
		}*/

	// Carol (shouldn't be able to do this) loads this file1
	file_fail, err := carol0004.LoadFile("file1")
	if reflect.DeepEqual(file_fail, []byte("I like pie")) {
		t.Error("Breach. Carol read a file that she wasn't supposed to")
	}

	// Alice shares file1 to Bob
	magic_stringAB, _ := alice0004.ShareFile("file1", "bob0004")

	// Bob loads before he calls receive
	_, err = bob0004.LoadFile("file1")
	if err == nil {
		t.Error("Cannot load a file shared to you before calling receivefile")
	}

	// Bob appends before he calls receive
	err = bob0004.AppendFile("file1", []byte("test"))
	if err == nil {
		t.Error("Cannot append to a file shared to you before calling receivefile")
	}

	// Bob receives file1
	bob0004.ReceiveFile("file1", "alice0004", magic_stringAB)
	// Bob shares file1 to Carol
	magic_stringBC, _ := bob0004.ShareFile("file1", "carol0004")

	// Bob receives file1 again, now under the name "fileBob"
	err = bob0004.ReceiveFile("fileBob", "alice0004", magic_stringAB)
	if err != nil {
		t.Error("Bob should be able to accept receiveFile twice on the same file with different chosen filename")
	}

	// Bob stores file1 (file1 already exists!) Bob's update should not change anything. (Implementation is actually undefined in the spec)
	bob0004.StoreFile("file1", []byte("yo"))
	file_fail, err = alice0004.LoadFile("file1")
	if !reflect.DeepEqual(file_fail, []byte("yo")) {
		t.Error("file1 contents incorrect when alice0004 loaded")
	}
	file_fail, err = bob0004.LoadFile("file1")
	if !reflect.DeepEqual(file_fail, []byte("yo")) {
		t.Error("file1 contents incorrect when bob0004 loaded")
	}

	// Carol loads file before calling receive
	_, err = carol0004.LoadFile("file1")
	if err == nil {
		t.Error("Carol cannot load a file shared to her before calling receivefile")
	}

	// Carol appends before calling receive
	err = carol0004.AppendFile("file1", []byte("test"))
	if err == nil {
		t.Error("Carol cannot append to a file shared to her before calling receivefile")
	}

	// Carol finally receives file1!
	carol0004.ReceiveFile("file1", "bob0004", magic_stringBC)

	// Alice shares file2 to Carol and Carol receives it properly
	magic_stringAC, _ := alice0004.ShareFile("file2", "carol0004")
	carol0004.ReceiveFile("file2", "alice0004", magic_stringAC)

	// Everyone loads their files and verifies content
	file1, err := alice0004.LoadFile("file1")
	if !reflect.DeepEqual(file1, []byte("yo")) {
		t.Error("file1 contents incorrect when alice0004 loaded")
	}

	file1, err = bob0004.LoadFile("file1")
	if !reflect.DeepEqual(file1, []byte("yo")) {
		t.Error("file1 contents incorrect when bob0004 loaded")
	}

	file1, err = carol0004.LoadFile("file1")
	if !reflect.DeepEqual(file1, []byte("yo")) {
		t.Error("file1 contents incorrect when carol0004 loaded")
	}

	file2, err := carol0004.LoadFile("file2")
	if !reflect.DeepEqual(file2, []byte("Trip to Russia")) {
		t.Error("file2 contents incorrect when carol0004 loaded")
	}

	// Everyone does some appending
	bob0004.AppendFile("file1", []byte(" Bob likes pie too."))

	alice0004.AppendFile("file1", []byte(" No you don't."))

	carol0004.AppendFile("file1", []byte(" Stop bickering."))

	carol0004.AppendFile("file2", []byte(" Russia is cool."))

	// Everyone loads files again and checks content
	file1, err = alice0004.LoadFile("file1")
	if !reflect.DeepEqual(file1, []byte("yo Bob likes pie too. No you don't. Stop bickering.")) {
		t.Error("file1 contents incorrect when alice0004 appended")
	}

	file1, err = bob0004.LoadFile("file1")
	if !reflect.DeepEqual(file1, []byte("yo Bob likes pie too. No you don't. Stop bickering.")) {
		t.Error("file1 contents incorrect when bob0004 appended")
	}

	file1, err = carol0004.LoadFile("file1")
	if !reflect.DeepEqual(file1, []byte("yo Bob likes pie too. No you don't. Stop bickering.")) {
		t.Error("file1 contents incorrect when carol0004 appended")
	}

	file2, err = alice0004.LoadFile("file2")
	if !reflect.DeepEqual(file2, []byte("Trip to Russia Russia is cool.")) {
		t.Error("file2 contents incorrect when carol0004 appended")
	}

	file2, err = carol0004.LoadFile("file2")
	if !reflect.DeepEqual(file2, []byte("Trip to Russia Russia is cool.")) {
		t.Error("file2 contents incorrect when carol0004 appended")
	}

	// Bob revokes access to file1
	err = bob0004.RevokeFile("file1")
	if err == nil {
		t.Error("Non-owners cannot revoke")
	}

	// Alice revokes access to file1
	err = alice0004.RevokeFile("file1")

	// Carol and Bob append to file1
	err = bob0004.AppendFile("file1", []byte("lol"))
	if err == nil {
		t.Error("Cannot append to file revoked from you")
	}
	err = carol0004.AppendFile("file1", []byte("lol"))
	if err == nil {
		t.Error("Cannot append to file revoked from you")
	}

	// Carol and Bob load file1
	_, err = bob0004.LoadFile("file1")
	if err == nil {
		t.Error("Cannot load file revoked from you")
	}

	_, err = carol0004.LoadFile("file1")
	if err == nil {
		t.Error("Cannot load file revoked from you")
	}

	// Carol and Bob call receiveFile
	err = bob0004.ReceiveFile("file1", "alice0004", magic_stringAB)
	if err == nil {
		t.Error("Cannot receive file revoked from you")
	}

	err = carol0004.ReceiveFile("file1", "bob0004", magic_stringBC)
	if err == nil {
		t.Error("Cannot receive file revoked from you")
	}
}

func TestComboAttack1(t *testing.T) {
	// clearing our datastore to simplify debugging
	userlib.DatastoreClear()
	//userlib.SetDebugStatus(true)
	// All users will use the same password for this test
	alice0006, err := InitUser("alice0006", "password")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user alice0006", err)
		return
	}

	bob0006, err := InitUser("bob0006", "password")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user bob0006", err)
		return
	}

	carol0006, err := InitUser("carol0006", "password")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user carol0006", err)
		return
	}

	alice0006.StoreFile("file1", []byte("Big Bear is Watching"))

	// alice shares file to non-existing user
	magic_string, err := alice0006.ShareFile("file1", "blob0006")
	if err == nil {
		t.Error("Failed to detect Alice shared filename to non-existing user")
	}

	// alice shares file correctly this time
	magic_string, err = alice0006.ShareFile("file1", "bob0006")

	// Bob receives file with incorrect magic_string
	magic_string_wrong := magic_string + "1"
	err = bob0006.ReceiveFile("file1", "alice0006", magic_string_wrong)
	if err == nil {
		t.Error("Failed to detect Bob received file with incorrect magic_string")
	}

	// Bob receives file with incorrect user, probably got a new Mac with the butterfly keyboard. Sad :(
	err = bob0006.ReceiveFile("file1", "aliccce0006", magic_string)
	if err == nil {
		t.Error("Failed to detect Bob received file with non-existing user")
	}

	// Bob recieves file with his own version's name. Should succeed
	err = bob0006.ReceiveFile("gile1", "alice0006", magic_string)
	if err != nil {
		t.Error("Error when bob receives file with different name")
	}

	// Bob receives same file with different chosen filename
	err = bob0006.ReceiveFile("file1", "alice0006", magic_string)
	if err != nil {
		t.Error("Error when bob receives file with different name 2")
	}

	// Bob loads both versions and checks contents
	file1, _ := bob0006.LoadFile("gile1")
	if !reflect.DeepEqual(file1, []byte("Big Bear is Watching")) {
		t.Error("Result from proper loading incorrect")
	}

	file1, _ = bob0006.LoadFile("file1")
	if !reflect.DeepEqual(file1, []byte("Big Bear is Watching")) {
		t.Error("Result from proper loading incorrect")
	}

	// Bob shares file to Carol
	magic_string, err = bob0006.ShareFile("file1", "carol0006")
	if err != nil {
		t.Error("Error when Bob shared file to Carol")
	}

	// Alice appends to file
	alice0006.AppendFile("file1", []byte(" You."))
	file1, _ = alice0006.LoadFile("file1")
	if !reflect.DeepEqual(file1, []byte("Big Bear is Watching You.")) {
		t.Error("Result from proper appending incorrect")
	}

	// Carol receives file (After Bob shared it and Alice appended to it)
	err = carol0006.ReceiveFile("file1", "bob0006", magic_string)
	if err != nil {
		t.Error("Carol receiving file caused error")
	}

	// Bob and Carol check file for correct contents
	file1, _ = carol0006.LoadFile("file1")
	if !reflect.DeepEqual(file1, []byte("Big Bear is Watching You.")) {
		t.Error("Result from Carol loading incorrect")
	}

	file1, _ = bob0006.LoadFile("file1")
	if !reflect.DeepEqual(file1, []byte("Big Bear is Watching You.")) {
		t.Error("Result from Bob loading incorrect")
	}

	entireDatastore := userlib.DatastoreGetMap()
	datastoreKeys := make([]userlib.UUID, len(entireDatastore))
	i := 0
	for k := range entireDatastore {
		datastoreKeys[i] = k
		i++
	}
	//userlib.DebugMsg("list: ", datastoreKeys)

	// Datastore tampers with file1
	alice0006SourceKey := userlib.Argon2Key([]byte("password"), []byte("alice0006"), 16)
	sharedFileMacKey, _ := userlib.HMACEval(alice0006SourceKey, []byte("file1"+"alice0006"+"sharesig"))
	file1Filename, _ := userlib.HMACEval(sharedFileMacKey[0:16], []byte("magic_string"))
	var file1UUID userlib.UUID
	// bytestouuid
	for x := range file1UUID {
		file1UUID[x] = file1Filename[x]
	}

	userlib.DatastoreSet(file1UUID, []byte("blabhaasdkfadfja;sdlkfja;sdlfka;sldfkasdfk"))

	// Everyone loads the tampered file (should fail)
	file1, err = alice0006.LoadFile("file1")
	if err == nil {
		t.Error("Failed to detect tampering in file data")
	}

	// Bob loads tampered file
	file1, err = bob0006.LoadFile("file1")
	if err == nil {
		t.Error("Failed to detect tampering in file data")
	}

	// Bob loads the other (untampered) file "gile1" that was actually the same file shared to him from Alice
	file1, err = bob0006.LoadFile("gile1")
	if err == nil {
		t.Error("Bob loading gile1 should still not work")
	}

	// Carol loads tampered file
	file1, err = carol0006.LoadFile("file1")
	if err == nil {
		t.Error("Failed to detect tampering in file data")
	}

	// Everyone appends to the tampered file (should fail)
	err = alice0006.AppendFile("file1", []byte("appending in vain"))
	if err == nil {
		t.Error("Failed to detect tampering in file data")
	}

	err = bob0006.AppendFile("file1", []byte("appending in vain"))
	if err == nil {
		t.Error("Failed to detect tampering in file data")
	}

	err = carol0006.AppendFile("file1", []byte("appending in vain"))
	if err == nil {
		t.Error("Failed to detect tampering in file data")
	}

	// Everyone shares the tampered file and calls receive (should fail)
	magic_string, err = alice0006.ShareFile("file1", "bob0006")
	err = bob0006.ReceiveFile("file1", "alice0006", magic_string)
	if err == nil {
		t.Error("Failed to detect tampering in file data")
	}

	magic_string, err = bob0006.ShareFile("file1", "alice0006")
	err = alice0006.ReceiveFile("file1", "bob0006", magic_string)
	if err == nil {
		t.Error("Failed to detect tampering in file data")
	}

	magic_string, err = carol0006.ShareFile("file1", "bob0006")
	err = bob0006.ReceiveFile("file1", "carol0006", magic_string)
	if err == nil {
		t.Error("Failed to detect tampering in file data")
	}

	// Everyone revokes the tampered file (should fail)
	err = bob0006.RevokeFile("file1")
	if err == nil {
		t.Error("Failed to detect tampering in file data")
	}

	err = alice0006.RevokeFile("file1")
	if err == nil {
		t.Error("Failed to detect tampering in file data")
	}

	err = carol0006.RevokeFile("file1")
	if err == nil {
		t.Error("Failed to detect tampering in file data")
	}
}

func TestComboAttack2(t *testing.T) {
	// clearing our datastore to simplify debugging
	userlib.DatastoreClear()
	userlib.SetDebugStatus(true)
	// All users will use the same password for this test
	alice0007, err := InitUser("alice0007", "password")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user alice0007", err)
		return
	}

	bob0007, err := InitUser("bob0007", "password")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user bob0007", err)
		return
	}

	alice0007.StoreFile("file1", []byte("Walking across the US in a straight line"))

	// Alice shares file to Bob
	magic_string, err := alice0007.ShareFile("file1", "bob0007")

	// Datastore tampers with file1
	alice0007SourceKey := userlib.Argon2Key([]byte("password"), []byte("alice0007"), 16)
	sharedFileMacKey, _ := userlib.HMACEval(alice0007SourceKey, []byte("file1"+"alice0007"+"sharesig"))
	file1Filename, _ := userlib.HMACEval(sharedFileMacKey[0:16], []byte("magic_string"))
	var file1UUID userlib.UUID
	// bytestouuid
	for x := range file1UUID {
		file1UUID[x] = file1Filename[x]
	}

	userlib.DatastoreSet(file1UUID, []byte("blabhaasdkfadfja;sdlkfja;sdlfka;sldfkasdfk"))

	// Alice loads file (should error)
	_, err = alice0007.LoadFile("file1")
	if err == nil {
		t.Error("Failed to detect tampering in file1")
	}

	// Bob receives file that was shared to him before datastore tampered with it (should error)
	err = bob0007.ReceiveFile("file1", "alice0007", magic_string)
	_, err = bob0007.LoadFile("file1") // err only detected when load
	if err == nil {
		t.Error("Failed to detect tampering in file1")
	}

	// Bob shares tampered file
	magic_string, err = bob0007.ShareFile("file1", "alice0007")
	err = alice0007.ReceiveFile("file1", "bob0007", magic_string) // err only detected when receive
	if err == nil {
		t.Error("Failed to detect tampering in file1")
	}

	// Alice shares tampered file
	magic_string, err = alice0007.ShareFile("file1", "bob0007") // err only detected when receive
	err = bob0007.ReceiveFile("file1", "alice0007", magic_string)
	if err == nil {
		t.Error("Failed to detect tampering in file1")
	}

	// Bob and Alice both revoke tampered file
	err = bob0007.RevokeFile("file1")
	if err == nil {
		t.Error("Failed to detect tampering in file1")
	}

	err = alice0007.RevokeFile("file1")
	if err == nil {
		t.Error("Failed to detect tampering in file1")
	}

	// Alice stores another file
	alice0007.StoreFile("file2", []byte("Walking across the US in a straight line"))

	// Alice loads this file
	file2, err := alice0007.LoadFile("file2")
	if err != nil || !reflect.DeepEqual(file2, []byte("Walking across the US in a straight line")) {
		t.Error("Error in loading file")
	}

	// Alice appends to this file
	err = alice0007.AppendFile("file2", []byte("."))
	if err != nil {
		t.Error("Error in appending file")
	}

	// Alice shares this file
	magic_string, err = alice0007.ShareFile("file2", "bob0007")
	if err != nil {
		t.Error("Share file failed")
	}

	// Bob receives this file
	err = bob0007.ReceiveFile("file2", "alice0007", magic_string)
	if err != nil {
		t.Error("Receive file failed")
	}

	// Bob creates his own file2  (already undefined behavior again)
	bob0007.StoreFile("file2", []byte("Bob's World"))

	// Get Alice's file2 UUID
	sharedFileMacKey, _ = userlib.HMACEval(alice0007SourceKey, []byte("file2"+"alice0007"+"sharesig"))
	file2Filename, _ := userlib.HMACEval(sharedFileMacKey[0:16], []byte("magic_string"))
	var file2UUIDAlice userlib.UUID
	// bytestouuid
	for x := range file1UUID {
		file2UUIDAlice[x] = file2Filename[x]
	}

	// Get Bob's file2 UUID
	bob0007SourceKey := userlib.Argon2Key([]byte("password"), []byte("bob0007"), 16)
	sharedFileMacKey, _ = userlib.HMACEval(bob0007SourceKey, []byte("file3"+"bob0007"+"sharesig"))
	file2Filename, _ = userlib.HMACEval(sharedFileMacKey[0:16], []byte("magic_string"))
	var file2UUIDBob userlib.UUID
	// bytestouuid
	for x := range file1UUID {
		file2UUIDBob[x] = file2Filename[x]
	}

	// Datastore tampers: Sets file2UUIDAlice contents = file2UUIDBob contents
	file2UUIDBobContents, _ := userlib.DatastoreGet(file2UUIDBob)
	userlib.DatastoreSet(file2UUIDAlice, file2UUIDBobContents)

	// Alice loads/appends (should error)
	file2, err = alice0007.LoadFile("file2")
	if err == nil {
		t.Error("Failed to detect datastore tampering")
	}

	err = alice0007.AppendFile("file2", []byte("yo wussup"))
	if err == nil {
		t.Error("Failed to detect datastore tampering")
	}

	// Bob loads a file of the same name (should fail, also a bit undefined in nature)
	file2, err = bob0007.LoadFile("file2")
	if err == nil {
		t.Error("Failed to detect datastore tampering")
	}

	magic_string, err = bob0007.ShareFile("file2", "alice0007")
	err = alice0007.ReceiveFile("file2", "bob0007", magic_string)
	if err == nil {
		t.Error("Failed to detect datastore tampering")
	}

	// Datastore clears everything
	userlib.DatastoreClear()

	// Alice and Bob try to do things in vain

	alice0007.StoreFile("filesarefun", []byte("what is this...."))
	_, err = alice0007.LoadFile("filesarefun")
	if err == nil {
		t.Error("The Datastore is empty goddammit")
	}

	err = alice0007.AppendFile("filesarefun", []byte("a"))
	if err == nil {
		t.Error("The Datastore is empty goddammit")
	}

	magic_string, err = alice0007.ShareFile("filesarefun", "bob0007")
	if err == nil {
		t.Error("The Datastore is empty goddammit")
	}

	err = bob0007.ReceiveFile("filesarefun", "alice0007", magic_string)
	if err == nil {
		t.Error("The Datastore is empty goddammit")
	}

	err = alice0007.RevokeFile("filesarefun")
	if err == nil {
		t.Error("The Datastore is empty goddammit")
	}
}

// err = nil -> success; err != nil -> fail
