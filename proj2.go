package proj2

// CS 161 Project 2 Spring 2020
// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder. We will be very upset.

import (
	// You need to add with:
	// go get github.com/cs161-staff/userlib
	"github.com/cs161-staff/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging, etc...
	"encoding/hex"

	// UUIDs are generated right based on the cryptographic PRNG
	// so lets make life easier and use those too...
	//
	// You need to add with: go get github.com/google/uuid
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"
	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
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

/*

classes:
	User: Holds user data
	UserBlob: wrapper struct for user which holds HMAC to ensure integrety
	FileSentinel: Utility struct that contains data about a file 
	SentinelBlob: Wrapper for sentinel that holds HMAC to ensure integrety
	FileNode: Node holds file data in a format that is similar to a linked list
	NodeBlob: Take a guess
	
Functions:
	User facing:
		initUser:
		getUser:
		StoreFile:
		LoadFile:
		AppendFile:
		ShareFile:
		ReciveFile:
		RevokeFile:
	Helpers:
		UnmarshCheck: unmashals a wrapper. computes an HMAC of the data within. compares 
					  reported HMAC with computed HMAC. returns unmarshalled data or error
		OverWriteHelper: Goes to a sentinel node and removes all data associated with a file
						from the persistant datastore. Then writes a new file to the same 
						location as pointed to by the senteiel node with appropriate wrappers
						and HMACS

*/

// The structure definition for a user record
type User struct {
	Username    string
	MasterKey   []byte               //will be used to verify password and generate other keys for the user
	LocationKey []byte               //will be used to find the location of the user in datastore
	SymKey      []byte               //will be used as this user's symmetric key for encryption
	HMACKey     []byte               //will be used as this user's HMACKey
	PrivateKey  userlib.PKEDecKey    //will be used as this user's private key
	DigSig      userlib.DSSignKey    //will be used to sign data from the user
	OwnedFiles  map[string]string //{hashed filename: uuid (location in Datastore)} files owned by this user
	SharedFiles map[string]string //{hashed filename: uuid (location in Datastore)} files shared with this user
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type UserBlob struct {
	UserData []byte //holds the encrypted data of the user instance
	HMAC []byte //holds the HMAC of the encrypted user data
}

//Represents the sentinel node of our Linked List for a given file
type FileSentinel struct {
	FirstUUID uuid.UUID //points to the first node of the linked list
	LastUUID uuid.UUID //points to the last node of the linked list (used for appending)
	Tree AccessTree //tree representing who has access to the given file
}

//A blob that encompasses a sentinel and holds its HMAC
type SentinelBlob struct {
	Sentinel []byte //holds the sentinel
	HMAC []byte //holds the HMAC of the sentinel
}

// Represents a general node in the linked list for a given file
type FileNode struct {
	DataUUID uuid.UUID //uuid of the data that this node represents (may be part of a file or an entire file)
	DataHMAC []byte //HMAC of the encrypted data
	NextUUID uuid.UUID //uuid of the next node in the linked list
}

type NodeBlob struct {
	Node []byte //holds the node
	NodeHMAC []byte //HMAC of the encrypted node
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the password has strong entropy, EXCEPT
// the attackers may possess a precomputed tables containing
// hashes of common passwords downloaded from the internet.
//NEED TO MAKE SEPARATE KEYS
func InitUser(username string, password string) (userdataptr *User, err error) {
	// check if this username is already in use
	_, exists := userlib.KeystoreGet(username + "_PKE")
	if exists {
		return nil, errors.New("This username already exists")
	}
	// create a new instance of a user
	var userdata User
	userdataptr = &userdata
	userdata.Username = username
	userdata.OwnedFiles = make(map[string]string)
	userdata.SharedFiles = make(map[string]string) //check this syntax
	// generate the master key
	MasterKey := userlib.Argon2Key([]byte(password), []byte(username), 16)
	userdata.MasterKey = MasterKey
	// generate keys
	HMACKey, HMACError := userlib.HashKDF(MasterKey, []byte("HMAC"))
	LocationKey, LocationError := userlib.HashKDF(MasterKey, []byte("Location"))
	SymKey, SymError := userlib.HashKDF(MasterKey, []byte("Symmetric Encryption"))
	PublicKeyEnc, PrivateKeyEnc, PKEError := userlib.PKEKeyGen()
	PrivateKeyDS, PublicKeyDS, DSError := userlib.DSKeyGen()
	//check for errors in key generation
	if HMACError != nil || LocationError != nil || SymError != nil || PKEError != nil || DSError != nil {
		return nil, errors.New("An error has occurred while generating the user's keys.")
	}
	//assign keys to userdata.Keys
	userdata.HMACKey = HMACKey[:16]
	userdata.LocationKey = LocationKey[:16]
	userdata.SymKey = SymKey[:32]
	userdata.PrivateKey = PrivateKeyEnc
	userdata.DigSig = PrivateKeyDS
	//store the public keys in keystore
	userlib.KeystoreSet(username+"_PKE", PublicKeyEnc)
	userlib.KeystoreSet(username+"_DS", PublicKeyDS)
	// userdata is now complete, now we must instantiate a Blob for this user to store securely in datastore
	var userblob UserBlob
	marshalledData, marshallError := json.Marshal(userdata)
	userblob.UserData = userlib.SymEnc(userdata.SymKey, userlib.RandomBytes(16), marshalledData)
	DataHMAC, MACError := userlib.HMACEval(userdata.HMACKey, userblob.UserData)
	userblob.HMAC = DataHMAC
	//store the blob in Datastore
	locationUUID, uuidError := uuid.FromBytes(userdata.LocationKey)
	marshalledBlob, marshallBlobError := json.Marshal(userblob)
	//check for errors in building blob intance
	if marshallError != nil || MACError != nil || uuidError != nil || marshallBlobError != nil {
		return nil, errors.New("An error has occured while encrypting the user information.")
	}
	userlib.DatastoreSet(locationUUID, marshalledBlob)
	//return a pointer to the user
	return &userdata, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.

//'im drawing a blank here dawg, we gotta like unencrypt our shit'
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	//first check if the user exists
	_, exists := userlib.KeystoreGet(username + "_PKE")
	if !exists {
		return nil, errors.New("The user cannot be found")
	}
	//now check if username and password are correct
	//generate the user's master key
	userMK := userlib.Argon2Key([]byte(password), []byte(username), 16)
	//generate the user's location key
	LocationKey, LocationError := userlib.HashKDF(userMK, []byte("Location"))
	locationUUID, uuidError := uuid.FromBytes(LocationKey[:16])
	//grab the blob from Datastore
	marshalled, correctInfo := userlib.DatastoreGet(locationUUID)
	if !correctInfo {
		return nil, errors.New("The username and/or password is incorrect")
	}
	//now check that the user data has not been tampered with
	//unmarshal the data
	var unmarshalled UserBlob
	marshalError1 := json.Unmarshal(marshalled, &unmarshalled)
	//unravel unmarshalleded blob object
	encryptedUser := unmarshalled.UserData
	reportedHMAC := unmarshalled.HMAC
	//generate the user's HMACKey
	HMACKey, HMACError := userlib.HashKDF(userMK, []byte("HMAC"))
	//compute HMAC from unencryptedUser
	actualHMAC, HMACGenError := userlib.HMACEval(HMACKey[:16], encryptedUser) //idk what this key is supposed to be
	//compare to reportedHMAC
	if !userlib.HMACEqual(reportedHMAC, actualHMAC) {
		return nil, errors.New("User data has been tampered with")
	}
	//If we reach this point, our user data is good to go, so we can assign it to userdata
	//generate the user's symmetric key
	SymKey, SymError := userlib.HashKDF(userMK, []byte("Symmetric Encryption"))
	//unencrypt then unmarshall the user data
	unencryptedMarshalledUser := userlib.SymDec(SymKey[:32], encryptedUser)
	unmarshalError2 := json.Unmarshal(unencryptedMarshalledUser, &userdata)
	if LocationError != nil || uuidError != nil || HMACError != nil || HMACGenError != nil || SymError != nil || marshalError1 != nil || unmarshalError2 != nil {
		return nil, errors.New("tuff shit. log off")
	}
	return userdataptr, nil
}

func unmarshCheckUserBlob(id uuid.UUID, EncKey []byte, HMACKey []byte)(user User, err error){
	var obj UserBlob
	marshalled, d_err := userlib.DatastoreGet(id)
	if d_err == false{
		return user, errors.New("Problem fetching from datastore")
	}
	m_error := json.Unmarshal(marshalled, &obj)
	if m_error != nil{
		return user, errors.New("Problem Unmarshalling blob")
	}
	reportedHMAC := obj.HMAC 
	//recompute HMAC based on data
	data := obj.UserData
	//marshalledData,m_err2 := json.Marshal(data)
	computedHMAC, hmac_err := userlib.HMACEval(HMACKey, data) 
	/*if m_err2 != nil{
		return user, errors.New("problem marshalling error when recomputing HMAC")
	}*/
	if hmac_err != nil{
		return user, errors.New("Error generating HMAC")
	}
	
	if userlib.HMACEqual(computedHMAC,reportedHMAC){
		return user, errors.New("MACs don't match. Data has been tampered with")
	}
	unencryptedMarshalled := userlib.SymDec(EncKey, data)
	m_error2 := json.Unmarshal(unencryptedMarshalled, &user) 
	if m_error2 != nil{
		return user, errors.New("Problem unmarshalling internal structure")
	}
	return user, nil
}

// checks HMAC for the sentinel node, returns unencrypted sentinel node
func unmarshCheckSentinelBlob(id uuid.UUID, EncKey []byte, HMACKey []byte)(sentinel FileSentinel, err error) {
	var obj SentinelBlob
	marshalled, success := userlib.DatastoreGet(id)
	if !success {
		return sentinel, errors.New("Problem finding object in datastore")
	} 
	MError := json.Unmarshal(marshalled, &obj) 
	if MError != nil{
		return sentinel, errors.New("Problem unmarshalling object")
	}
	reportedHMAC := obj.HMAC
	//recompute HMAC based on data
	data := obj.Sentinel
	computedHMAC, HMACError := userlib.HMACEval(HMACKey, data)
	if HMACError != nil {
		return sentinel, errors.New("Problem recomputing HMAC")
	}
	if !userlib.HMACEqual(computedHMAC, reportedHMAC){
		return sentinel, errors.New("HMACs don't match. Data has been tampered with")
	}
	unencryptedMarshalled := userlib.SymDec(EncKey, data)
	MError3 := json.Unmarshal(unencryptedMarshalled, &sentinel)
	if MError3 != nil{
		return sentinel, errors.New("Problem unmarshalling inner structure")
	}
	return sentinel, nil	
}

func unmarshCheckFileBlob(id uuid.UUID, EncKey []byte, HMACKey []byte)(node FileNode, err error){
	var obj NodeBlob
	marshalled, DSError := userlib.DatastoreGet(id)
	if !DSError{
		return node, errors.New("Problem retriving from the datastore")
	}
	MError := json.Unmarshal(marshalled, &obj)
	if MError != nil{
		return node, errors.New("Problem unmarshalling outer structure")
	}
	reportedHMAC := obj.NodeHMAC
	//recompute HMAC based on data
	data := obj.Node
	computedHMAC,HMACError:= userlib.HMACEval(HMACKey, data)
	if HMACError != nil {
		return node, errors.New("Problem generating HMAC")
	}
	if !userlib.HMACEqual(reportedHMAC, computedHMAC){
		return node, errors.New("HMACs don't match. Data has been tampered with")
	}
	unencryptedMarshalled := userlib.SymDec(EncKey, data)
	MError3 := json.Unmarshal(unencryptedMarshalled, &node)
	if MError3 != nil{
		return node, errors.New("Problem unmarshalling internal struct")
	}
	return node, nil
}

func checkFile(node FileNode, HMACKey []byte)(curr uuid.UUID, next uuid.UUID, err error){
	// checks the HMAC of the data to ensure its integrity
	fileptr := node.DataUUID
	filedata,DSError := userlib.DatastoreGet(fileptr)
	if !DSError{
		return curr, next, errors.New("Problem finding file in datastore")
	}
	reportedHMAC := node.DataHMAC
	computedHMAC,HMACError := userlib.HMACEval(HMACKey, filedata)
	if HMACError != nil{
		return curr, next, errors.New("Problem generating HMAC")
	}
	if !userlib.HMACEqual(reportedHMAC, computedHMAC){
		return curr, next, errors.New("File has been tampered with")
	} else {
		return node.DataUUID, node.NextUUID, nil
	}
}

func overwriteHelper(username string, accessToken string, data []byte)(err error){
	//pull up sentinel node
	sentUUID, SymEncKey, HMACKey, genKErr := generateKeys(username, accessToken)
	if genKErr != nil{
		return errors.New("Problem generating keys in overwite helper")
	}
	sentinel, SentBlobError := unmarshCheckSentinelBlob(sentUUID, SymEncKey, HMACKey)
	if SentBlobError != nil{
		return errors.New("Could not retive file")
	}
	///////ADDED PERMISION CHECK
	if _, ok := sentinel.Tree.Access[username]; !ok {
		return errors.New("User does not have permission")
	}
	nodeUUID := sentinel.FirstUUID //points to a FileNode
	//heres where we actully start removing stuff
	for (nodeUUID != sentUUID){ //and check that first is in the datastore
		filenode, filenodeerror := unmarshCheckFileBlob(nodeUUID, SymEncKey, HMACKey)
		dataID, nextID, fileError := checkFile(filenode, HMACKey)
		if filenodeerror != nil || fileError != nil{
			return errors.New("Problem deleting files")
		}
		userlib.DatastoreDelete(nodeUUID)
		nodeUUID = nextID
		userlib.DatastoreDelete(dataID)
	}
	//encrypt data 
	// need to generate uuids to be stored in datastore (sentUUID will also stored in userdata)
	dataUUID := uuid.New() //location in Datastore where the file data will be stored
	nodeUUID = uuid.New() //location in datastore where the node will be stored
	//encrypt the data and generate its HMAC
	encryptedData := userlib.SymEnc(SymEncKey, userlib.RandomBytes(16), data)//encrypted data
	dataHMAC, dataHMACErr := userlib.HMACEval(HMACKey, encryptedData) //HMAC of the encrypted data
	if dataHMACErr != nil {
		return errors.New("Error creating HMAC in overwrite helper")
	}
	// need to create a new linked list for the file and store it in datastore
	// start by initializing the sentinel node
	sentinel.FirstUUID = nodeUUID //points to the node
	sentinel.LastUUID = nodeUUID //points to the node
	// next initialize the node 
	var node FileNode
	node.DataUUID = dataUUID //points to location where data will be stored
	node.DataHMAC = dataHMAC //the HMAC of the encrypted data
	node.NextUUID = sentUUID //points to "next" node (sentinel in this case since its the 'last' node)
	// now that the sentinel and the node are created, we must marshal and encrypt them
	sMarsh, sMarshErr := json.Marshal(sentinel) 
	if sMarshErr != nil{
		return errors.New("Problem marshalling sentinel in overwrite helper")
	}
	encryptedSentinel := userlib.SymEnc(SymEncKey, userlib.RandomBytes(16), sMarsh)//encrypted sentinel
	nMarsh, nMarshErr := json.Marshal(node)
	if nMarshErr != nil{
		return errors.New("Problem Marshalling node in overwrite helper")
	}
	encryptedNode := userlib.SymEnc(SymEncKey, userlib.RandomBytes(16), nMarsh)//encrypted node
	// now initialize the blobs
	var sBlob SentinelBlob
	var nBlob NodeBlob
	sBlob.Sentinel = encryptedSentinel
	sHMAC, sHMACErr := userlib.HMACEval(HMACKey, encryptedSentinel) //HMAC of the encrypted sentinel node
	if sHMACErr!=nil{
		return errors.New("Problem generating HMAC in overwrite error")
	}
	sBlob.HMAC = sHMAC
	nBlob.Node = encryptedNode
	nHMAC, nHMACErr := userlib.HMACEval(HMACKey, encryptedNode) //HMAC of the encrypted node
	if nHMACErr != nil{
		return errors.New("Problem generating HMAC in overwrite error")
	}
	nBlob.NodeHMAC = nHMAC
	// now that everything has been properly created, we must store it in Datastore
	sBlobMarsh, sbmErr := json.Marshal(sBlob)
	nBlobMarsh, nbmErr := json.Marshal(nBlob)
	if sbmErr != nil || nbmErr != nil{
		return errors.New("Problem marshalling file in overwrite helper")
	}
	userlib.DatastoreSet(sentUUID, sBlobMarsh) //store the sentinel blob at sentUUID
	userlib.DatastoreSet(nodeUUID, nBlobMarsh) //store the node blob at nodeUUID
	userlib.DatastoreSet(dataUUID, encryptedData) //store the encrypted data at dataUUID
	return nil
}

// This stores a file in the datastore.
//
// The plaintext of the filename + the plaintext and length of the filename
// should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	filename = filename + "_" //ensures stored filename isn't empty (allows us to use as key in map)
	data = append(data, []byte("____")...) //ensures stored data isn't empty (for encryption purposes)
	//Check if filename is in owned files
	if accessToken, ok := userdata.OwnedFiles[filename]; ok {
		//overwrite this file with data
		overwriteHelper(userdata.Username, accessToken, data)
	} else if accessToken2, ok2 := userdata.SharedFiles[filename]; ok2 {
		//overwrite the file with this data
		revokedPremission := overwriteHelper(userdata.Username, accessToken2, data)
		if revokedPremission != nil{
			//probably means file access has been revoked. removed from user.shared with me
			delete(userdata.SharedFiles, filename)
		}
	} else {
		// need to generate uuids to be stored in datastore (sentUUID will also stored in userdata)
		uuidBytes := userlib.RandomBytes(16) // bytes used to generate the sentinel uuid
		sentUUID, _ := uuid.FromBytes(uuidBytes) //location in Datastore where sentinel node will be stored
		accessToken := newAccessToken(userdata.Username, uuidBytes) // accessToken for this user and file
		dataUUID := uuid.New() //location in Datastore where the file data will be stored
		nodeUUID := uuid.New() //location in datastore where the node will be stored
		userdata.OwnedFiles[filename] = accessToken // the accessToken can now be accessed from userdata.OwnedFiles[filename]
		// now we must generate the keys that we need in order to properly encrypt/authenticate
		_, SymEncKey, HMACKey, _ := generateKeys(userdata.Username, accessToken)
		//encrypt the data and generate its HMAC
		encryptedData := userlib.SymEnc(SymEncKey, userlib.RandomBytes(16), data)//encrypted data
		dataHMAC, _ := userlib.HMACEval(HMACKey, encryptedData) //HMAC of the encrypted data
		// need to create a new linked list for the file and store it in datastore
		// start by initializing the sentinel node
		var fileSent FileSentinel
		fileSent.FirstUUID = nodeUUID //points to the node
		fileSent.LastUUID = nodeUUID //points to the node
		fileSent.Tree = initATree(userdata.Username)
		// next initialize the node 
		var node FileNode
		node.DataUUID = dataUUID //points to location where data will be stored
		node.DataHMAC = dataHMAC //the HMAC of the encrypted data
		node.NextUUID = sentUUID //points to "next" node (sentinel in this case since its the 'last' node)
		// now that the sentinel and the node are created, we must marshal and encrypt them
		sMarsh, _ := json.Marshal(fileSent) 
		encryptedSentinel := userlib.SymEnc(SymEncKey, userlib.RandomBytes(16), sMarsh)//encrypted sentinel
		nMarsh, _ := json.Marshal(node)
		encryptedNode := userlib.SymEnc(SymEncKey, userlib.RandomBytes(16), nMarsh)//encrypted node
		// now initialize the blobs
		var sBlob SentinelBlob
		var nBlob NodeBlob
		sBlob.Sentinel = encryptedSentinel
		sHMAC, _ := userlib.HMACEval(HMACKey, encryptedSentinel) //HMAC of the encrypted sentinel node
		sBlob.HMAC = sHMAC
		nBlob.Node = encryptedNode
		nHMAC, _ := userlib.HMACEval(HMACKey, encryptedNode) //HMAC of the encrypted node
		nBlob.NodeHMAC = nHMAC
		// now that everything has been properly created, we must store it in Datastore
		sBlobMarsh, _ := json.Marshal(sBlob)
		nBlobMarsh, _ := json.Marshal(nBlob)
		userlib.DatastoreSet(sentUUID, sBlobMarsh) //store the sentinel blob at sentUUID
		userlib.DatastoreSet(nodeUUID, nBlobMarsh) //store the node blob at nodeUUID
		userlib.DatastoreSet(dataUUID, encryptedData) //store the encrypted data at dataUUID
	}
	return
}
// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	filename = filename + "_" //ensures stored filename isn't empty (allows us to use as key in map)
	data = append(data, []byte("____")...) //ensures stored data isn't empty (for encryption purposes)
	sentinel, sentinelUUID, SymEncKey, HMACKey, gskErr := getSentinelAndKeys(userdata, filename) //gets us the sentinel node and its UUID of the file we're trying to load and the keys for HMAC and Encryption (also checks HMAC of sentinel)
	if gskErr != nil {
		return errors.New("Error in generating the sentinel")
	}
	//lets start by encrypting and HMACing the data and generating the uuid of where to store it
	encryptedData := userlib.SymEnc(SymEncKey,userlib.RandomBytes(16), data)
	dataHMAC, dHMACErr := userlib.HMACEval(HMACKey, encryptedData)
	if dHMACErr != nil {
		return errors.New("Error in generating the HMAC of the data")
	}
	dataUUID := uuid.New()
	//next lets create the new node and its blob (handle encryption and MACing)
	var node FileNode
	node.DataUUID = dataUUID
	node.DataHMAC = dataHMAC
	node.NextUUID = sentinelUUID //points back to the sentinel since its the last part of the node
	marshalledNode, nMarshErr := json.Marshal(node)
	if nMarshErr != nil {
		return errors.New("Error in marshalling the node")
	}
	encryptedNode := userlib.SymEnc(SymEncKey, userlib.RandomBytes(16),  marshalledNode)
	nodeHMAC, nHMACErr := userlib.HMACEval(HMACKey, encryptedNode)
	if nHMACErr != nil {
		return errors.New("Error in calculating the HMAC of the node")
	}
	var nBlob NodeBlob
	nBlob.Node = encryptedNode
	nBlob.NodeHMAC = nodeHMAC
	// generate the uuid to store the node blob at
	nodeUUID := uuid.New()
	//lets now edit the current 'last node' so that it points to our new node instead of the sentinel
	lastNodeUUID := sentinel.LastUUID //the uuid of the last node of the linked list
	lastNode, FileBlobError := unmarshCheckFileBlob(lastNodeUUID, SymEncKey, HMACKey) //last node is the unencrypted last node in the linked list
	if FileBlobError != nil {
		return errors.New("Error in unmarshalling the last node")
	}
	lastNode.NextUUID = nodeUUID
	// now lets reencrypt/HMAC the old last node and put it in a blob
	marshalledLast, lMarshErr := json.Marshal(lastNode)
	if lMarshErr != nil {
		return errors.New("Error in marshalling the last node")
	}
	encryptedLast := userlib.SymEnc(SymEncKey, userlib.RandomBytes(16), marshalledLast)
	lastHMAC, lHMACErr := userlib.HMACEval(HMACKey, encryptedLast)
	if lHMACErr != nil {
		return errors.New("Error in calculating HMAC of the last node")
	}
	var lastBlob NodeBlob
	lastBlob.Node = encryptedLast
	lastBlob.NodeHMAC = lastHMAC
	// now we need to update the sentinel node, re-encrypt/HMAC, and put it in a blob
	sentinel.LastUUID = nodeUUID
	marshalledSent, sMarshErr := json.Marshal(sentinel)
	if sMarshErr != nil {
		return errors.New("Error in marshalling the sentinel node")
	}
	encryptedSentinel := userlib.SymEnc(SymEncKey, userlib.RandomBytes(16), marshalledSent)
	sentHMAC, sHMACErr := userlib.HMACEval(HMACKey, encryptedSentinel)
	if sHMACErr != nil {
		return errors.New("Error in computing the HMAC of the sentinel")
	}
	var sBlob SentinelBlob
	sBlob.Sentinel = encryptedSentinel
	sBlob.HMAC = sentHMAC
	// all that's left to do is marshal our blobs and store everything in datastore!
	sMarsh, sErr := json.Marshal(sBlob)
	if sErr != nil {
		return errors.New("Error in marshalling the sentinel blob")
	}
	lMarsh, lErr := json.Marshal(lastBlob)
	if lErr != nil {
		return errors.New("Error in marshalling the last blob")
	}
	nMarsh, nErr := json.Marshal(nBlob)
	if nErr != nil {
		return errors.New("Error in marshalling the appended blob")
	}
	userlib.DatastoreSet(nodeUUID, nMarsh)
	userlib.DatastoreSet(lastNodeUUID, lMarsh)
	userlib.DatastoreSet(sentinelUUID, sMarsh)
	userlib.DatastoreSet(dataUUID, encryptedData)
	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	filename = filename + "_" //ensures stored filename isn't empty (allows us to use as key in map)
	sentinel, sentinelUUID, SymEncKey, HMACKey, gskErr := getSentinelAndKeys(userdata, filename) //gets us the sentinel node and its UUID of the file we're trying to load and the keys for HMAC and Encryption (also checks HMAC of sentinel)
	//check if user has access accoreding to the sentinel
	if _,ok := sentinel.Tree.Access[userdata.Username]; !ok{
		//sentinel says we dont have access so we delete from users shared files
		delete(userdata.SharedFiles, filename)
		return nil, errors.New("You no longer have access")
	}
	if gskErr != nil{
		return data, errors.New("Problem generating keys in loaddfile()")
	}
	nodeUUID := sentinel.FirstUUID //uuid of the first node in the linked list
	var node FileNode // will be used to store the unencrypted node
	var FileBlobError error
	var CheckFileError error
	var dataUUID uuid.UUID // will be used to store the uuid of the data of the current node
	var dataToBeAppended []byte // will be used to hold the encrypted data we wish to append to data
	var ok bool //used to ensure DatastoreGet retrieves data
	for true {
		node, FileBlobError = unmarshCheckFileBlob(nodeUUID, SymEncKey, HMACKey)
		if FileBlobError != nil {
			return data, errors.New("Problem unmarshalling file")
		}
		dataUUID, nodeUUID, CheckFileError = checkFile(node, HMACKey) //stores location of the data for this file node in dataUUID and checks its MAC, sets nodeUUID = node.NextUUID
		if err != CheckFileError {
			return data, errors.New("Problem in check file")
		}
		dataToBeAppended, ok = userlib.DatastoreGet(dataUUID) // sets dataToBeAppended to be the encrypted data at dataUUID
		if !ok {
			return data, errors.New("Uh oh, the data uuid isn't a valid key in datastore ):")
		}
		data = append(data, userlib.SymDec(SymEncKey, dataToBeAppended)...)
		data = data[:len(data)-4] // removes the '____' at the end of each chunk of data
		if nodeUUID == sentinelUUID {
			break
		}
	}
	return data, nil
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
func (userdata *User) ShareFile(filename string, recipient string) (magic_string string, err error) {
	//initial check to see if user has access to filename
	/*if _, ok := userdata.OwnedFiles[filename]; !ok {
		//the user does not have access to the file
		return "", errors.New("You do not have access to the file that you are trying to share")
	} else if _, ok2 := userdata.OwnedFiles[filename]; !ok2 {
		return "", errors.New("You do not have access to the file that you are trying to share")
	}*/
	if !checkIfUserExists(recipient) {
		return "", errors.New("The user who you are trying to share this file with does not exist")
	}
	filename = filename + "_" //ensures stored filename isn't empty (allows us to use as key in map)
	sentinel, sentinelUUID, SymEncKey, HMACKey, gskErr := getSentinelAndKeys(userdata, filename) //gets us the sentinel node and its UUID of the file we're trying to load and the keys for HMAC and Encryption (also checks HMAC of sentinel)
	if gskErr != nil{
		return "", errors.New("Problem generating keys in ShareFile")
	}
	// check to make sure that the user has access in the accesstree
	_, treeAccess := sentinel.Tree.Access[userdata.Username]
	if !treeAccess {
		//user does not have access in sentinel tree
		return "", errors.New("You do not have access to the file that you are trying to share")
	}
	//add access to tree
	treeAddErr := treeAdd(sentinel.Tree, userdata.Username, recipient)
	if treeAddErr != nil {
		return "", treeAddErr
	}
	//now we need to re-encrypt the sentinel, compute its MAC, and store the blob back in Datastore
	marshalledSentinel, marshSentErr := json.Marshal(sentinel)
	if marshSentErr != nil {
		return "", errors.New("Error while marshalling the sentinel")
	}
	
	encryptedSentinel := userlib.SymEnc(SymEncKey, userlib.RandomBytes(16), marshalledSentinel)
	sentHMAC, sHMACErr := userlib.HMACEval(HMACKey, encryptedSentinel)
	
	if sHMACErr != nil{
		return "", errors.New("HMAC Error in sharefile")
	}
	var sBlob SentinelBlob
	sBlob.Sentinel = encryptedSentinel
	sBlob.HMAC = sentHMAC
	sMarsh, sMarshErr := json.Marshal(sBlob)
	if sMarshErr != nil{
		return "", errors.New("Marshalling error in sharefile")
	}
	userlib.DatastoreSet(sentinelUUID, sMarsh)
	//fmt.Println("share file uuid1 (sentinel)", sentinelUUID)
	//we must now generate the access token to share with the recipient
	//generate the bytes that resutl in the correct uuid
	var userToken string //holds the accesstoken for the current user
	if _, ok := userdata.OwnedFiles[filename]; ok {
		userToken = userdata.OwnedFiles[filename]
	} else {
		userToken = userdata.SharedFiles[filename]
	}
	//data := ParseToken(userdata.Username, userToken)
	// use uuidBytes to generate a new accesstoken
	accessToken := []byte(sharedAccessToken(userdata.Username, userToken, recipient))
	// now all that's left to do is encrypt the token and sign it
	pubKey, pkOK := userlib.KeystoreGet(recipient+"_PKE")
	if !pkOK {
		return "", errors.New("The recipient doesn't have a public key in keystore")
	}
	signKey := userdata.DigSig
	encryptedToken1, encErr := userlib.PKEEnc(pubKey, accessToken[:96])
	encryptedToken2, encErr2 := userlib.PKEEnc(pubKey, accessToken[96:])
	if encErr != nil || encErr2 != nil {
		return "", errors.New("There was an error encrypting the access token")
	}
	encryptedToken := append(encryptedToken1, encryptedToken2...)
	signature, sigError := userlib.DSSign(signKey, encryptedToken)
	if sigError != nil {
		return "", errors.New("Error signing the accesstoken (probably cuz mcclain was licking my nuts)")
	}
	//fmt.Println("LENGTHS", len(encryptedToken))
	magic_bytes := append(encryptedToken, signature...)
	magic_string = hex.EncodeToString(magic_bytes)//hex.EncodeToString(encryptedToken) + hex.EncodeToString(signature)
	//fmt.Println(len(magic_string))
	return magic_string, nil
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string, magic_string string) error {
	//we must first verify the magic_string and decrypt the accesstoken from it
	filename = filename + "_" //ensures stored filename isn't empty (allows us to use as key in map)
	if _, ok := userdata.OwnedFiles[filename]; ok {
		//the user already has a file with this name
		return errors.New("A file with this filename already exists for this user.")
	}
	privKey := userdata.PrivateKey
	verifyKey, DSKeyOK := userlib.KeystoreGet(sender+"_DS")
	if !DSKeyOK {
		return errors.New("Unable to find the senders verification key")
	}
	magic_bytes, _ := hex.DecodeString(magic_string)
	if len(magic_bytes) < 512 {
		return errors.New("Save me from a panic")
	}
	encryptedAccessToken := magic_bytes[:512]
	signature := magic_bytes[512:]
	verificationError := userlib.DSVerify(verifyKey, encryptedAccessToken, signature)
	if verificationError != nil {
		return errors.New("Error when verifying signature")
	}
	//we now decrypt the two halves of the access token
	accTok1, decErr1 := userlib.PKEDec(privKey, encryptedAccessToken[:256])
	accTok2, decErr2 := userlib.PKEDec(privKey, encryptedAccessToken[256:])
	if decErr1 != nil || decErr2 != nil {
		return errors.New("Error when decrypting access token")
	}
	accessTokenBytes := append(accTok1, accTok2...)
	accessToken := string(accessTokenBytes) // is this corret?
	// now let's confirm that the user still has access in the sentinel tree
	id, SymEncKey, HMACKey, getKeyErr := generateKeys(userdata.Username, accessToken)
	if getKeyErr != nil {
		return errors.New("key gen error in recive file")
	}
	sentBlob, succ := userlib.DatastoreGet(id)
	if !succ {
		return errors.New("Unable to get the sentinel")
	}
	var s SentinelBlob
	unmarshalledSentErr := json.Unmarshal(sentBlob, &s)
	if unmarshalledSentErr != nil{
		return errors.New("Unmarshalling error in Recive file")
	}
	computedHMAC, HMACErr := userlib.HMACEval(HMACKey, s.Sentinel)
	if HMACErr != nil {
		return errors.New("Error generating sentinel's HMAC")
	}
	sentIntegrity := userlib.HMACEqual(s.HMAC, computedHMAC)
	if !sentIntegrity {
		//fmt.Println("Computed HMAC", computedHMAC)
		return errors.New("The sentinel has no integrity")
	}
	sentinelMarshalled := userlib.SymDec(SymEncKey, s.Sentinel)
	var sent FileSentinel
	err := json.Unmarshal(sentinelMarshalled, &sent)
	if err != nil{
		return errors.New("problem unmarshalling inner struct in recive file")
	}
	_, hasAccess := sent.Tree.Access[userdata.Username]
	if hasAccess { // if the user has access
		userdata.SharedFiles[filename] = accessToken
	}
	return nil
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
	if !checkIfUserExists(target_username) {
		return errors.New("The user whose access you are trying to revoke does not exist")
	}
	//pull up sentinel for the associated owned file
	filename = filename + "_" //ensures stored filename isn't empty (allows us to use as key in map)
	sentinel, sentinelUUID, SymEncKey, HMACKey, gskErr := getSentinelAndKeys(userdata, filename) //gets us the sentinel node and its UUID of the file we're trying to load and the keys for HMAC and Encryption (also checks HMAC of sentinel)
	if gskErr != nil{
		return errors.New("Problem generating keys in RevokeFile")
	}
	//remove the user from the access tree
	UserRemoveError := treeRemove(sentinel.Tree, target_username, userdata.Username)
	if UserRemoveError != nil{
		return errors.New("Problem when removing user from tree")
	}
	//put the sentinel back on the data store 
	marshalledSentinel, marshSentErr := json.Marshal(sentinel)
	if marshSentErr != nil {
		return errors.New("Error while marshalling the sentinel")
	}
	encryptedSentinel := userlib.SymEnc(SymEncKey, userlib.RandomBytes(16), marshalledSentinel)
	sentHMAC, sHMACErr := userlib.HMACEval(HMACKey, encryptedSentinel)
	if sHMACErr != nil{
		return errors.New("HMAC Error in sharefile")
	}
	var sBlob SentinelBlob
	sBlob.Sentinel = encryptedSentinel
	sBlob.HMAC = sentHMAC
	sMarsh, sMarshErr := json.Marshal(sBlob)
	if sMarshErr != nil{
		return errors.New("Marshalling error in sharefile")
	}
	userlib.DatastoreSet(sentinelUUID, sMarsh)
	return nil
}

//helper function that checks if a given username exists
func checkIfUserExists(username string) (exists bool){
	_, exists = userlib.KeystoreGet(username+"_PKE")
	return exists
}

//Returns a new access token to be used by the owner of a newly created file
func newAccessToken(username string, uuidBytes []byte) (accessToken string) {
	data := append(uuidBytes, userlib.RandomBytes(16)...)
	accessToken = generateAccessToken(data, username)
	return accessToken
}

//creates an accesstoken to be shared with receiver, using the information from sender's access token
func sharedAccessToken(sender string, senderAccessToken string, recipient string) (accessToken string) {
	data := parseToken(sender, senderAccessToken)
	accessToken = generateAccessToken(data, recipient)
	return accessToken
}

//helper function to generate an access token given the data to be stored and the username of the token recipient
func generateAccessToken(data []byte, username string) (accessToken string) {
	aTK1 := userlib.RandomBytes(16)
	aTK2 := userlib.RandomBytes(16)
	key1, _ := userlib.HashKDF(aTK1, []byte(username))
	key1 = key1[:32]
	key2, _ := userlib.HashKDF(aTK2, key1)
	key2 = key2[:32]
	redBlock := userlib.SymEnc(key2, userlib.RandomBytes(16), data)
	inner := append(aTK2, redBlock...)
	blueBlock := userlib.SymEnc(key1, userlib.RandomBytes(16), inner)
	accessToken = hex.EncodeToString(append(aTK1, blueBlock...))
	return accessToken
}

//parses a token and returns the data within
/*func parseToken(username string, accToken string)(data []byte){
	atk1 := []byte(accToken[:16])
	blueKey, _ := userlib.HashKDF(atk1, []byte(username))
	blueKey = blueKey[:32]
	chunk2 := []byte(accToken[len(atk1):])
	inner := userlib.SymDec(blueKey, chunk2)
	atk2 := []byte(inner[:16])
	redKey, _ := userlib.HashKDF(atk2, blueKey)
	redKey = redKey[:32]
	rgdata := inner[len(atk2):]
	data = userlib.SymDec(redKey,rgdata)
	return data
}*/

//parses a token and returns the data within
func parseToken(username string, accToken string)(data []byte){ //i think the problem is here
	accessToken, _ := hex.DecodeString(accToken)
	atk1 := accessToken[:16]
	blueKey, _ := userlib.HashKDF(atk1, []byte(username))
	blueKey = blueKey[:32]
	chunk2 := accessToken[len(atk1):]
	inner := userlib.SymDec(blueKey, chunk2)
	atk2 := inner[:16]
	redKey, _ := userlib.HashKDF(atk2, blueKey)
	redKey = redKey[:32]
	rgdata := inner[len(atk2):]
	data = userlib.SymDec(redKey,rgdata)
	return data
}

//helper function to generate the necessary keys to decrypt/validate a file
//returns uuid, SymEncKey, HMACKey
func generateKeys(username string, accessToken string) (id uuid.UUID, SymEncKey []byte, HMACKey []byte, err error) {
	//fmt.Println("Access token in generate keys: ", username, accessToken)
	//fmt.Println()
	data := parseToken(username, accessToken)
	//fmt.Println("Data", data)
	idBytes := data[:16]
	id, _ = uuid.FromBytes(idBytes) //is this correct?
	key := data[16:] //what the hell
	SymKey, SymKeyErr := userlib.HashKDF(key[:16], append(idBytes, []byte("SymEncKey")...))
	SymEncKey = SymKey[:32]
	HKey, HMACKeyErr := userlib.HashKDF(key[:16], append(idBytes, []byte("HMACKey")...))
	if SymKeyErr != nil || HMACKeyErr != nil{
		return id, SymEncKey, HMACKey, errors.New("Key generation error")
	}
	HMACKey = HKey[:16]
	return id, SymEncKey, HMACKey, nil
}

// helper function to execute the initial logic for loading/appending to a file
func getSentinelAndKeys(userdata *User, filename string)(sentinel FileSentinel, sentinelUUID uuid.UUID, SymEncKey []byte, HMACKey []byte, err error){
	//check access and find file info in the user
	//check if user owns it
	if accessToken1, ok := userdata.OwnedFiles[filename]; ok {
		sentinelUUID, SymEncKey, HMACKey, KeyGenError := generateKeys(userdata.Username, accessToken1)
		if KeyGenError != nil{
			return sentinel, sentinelUUID, SymEncKey, HMACKey, errors.New("Problem generating keys in getSentinelAndKeys")
		}
		sentinel,  SentError := unmarshCheckSentinelBlob(sentinelUUID, SymEncKey, HMACKey)
		if SentError != nil{
			return sentinel, sentinelUUID, SymEncKey, HMACKey, errors.New("Problem generating sentinel in getSentinelAndKeys")
		}
		return sentinel, sentinelUUID, SymEncKey, HMACKey, nil
	} else if accessToken2, ok2 := userdata.SharedFiles[filename]; ok2 {
		sentinelUUID, SymEncKey, HMACKey, KeyGenError := generateKeys(userdata.Username, accessToken2)
		if KeyGenError != nil{
			return sentinel, sentinelUUID, SymEncKey, HMACKey, errors.New("Problem generating keys in getSentinelAndKeys")
		}
		sentinel,  SentError := unmarshCheckSentinelBlob(sentinelUUID, SymEncKey, HMACKey)
		if SentError != nil{
			return sentinel, sentinelUUID, SymEncKey, HMACKey, errors.New("Problem generating sentinel in getSentinelAndKeys")
		}
		return sentinel, sentinelUUID, SymEncKey, HMACKey, nil
	} 
	return sentinel, sentinelUUID, SymEncKey, HMACKey, errors.New("It does not appear that this user owns this file")
}

//struct representing an access tree
type AccessTree struct {
	Owner string
	Access map[string][]string
}

func initATree(owner string)(t AccessTree){
	t.Owner = owner
	t.Access = make(map[string][]string)
	t.Access[owner] = make([]string, 0)
	return t
}

//function to add a user to the access tree
func treeAdd(t AccessTree, parent string, child string) (err error){
	//check that they have file access
	tree := t.Access
	if _, ok := tree[parent]; !ok {
		return errors.New("User not found in access tree")
	}
	children := tree[parent]
	tree[parent] = append(children, child)
	tree[child] = make([]string, 0)
	return nil
}

//function to remove a user from the access tree
func treeRemove(t AccessTree, toRemove string, caller string)(err error){
	if t.Owner != caller {
		return errors.New("Only the owner of a file can revoke access to it")
	}
	direct_children := t.Access[caller]
	for _, child := range direct_children {
		if child == toRemove {
			return treeRemoveHelper(t.Access, toRemove)
		}
	}
	return errors.New("Only direct children can be removed from the access tree")
}

/*
func remove(slice []int, s int) []int {
    return append(slice[:s], slice[s+1:]...)
}*/

func treeRemoveHelper(tree map[string][]string, toRemove string) (err error) {
	if _, ok := tree[toRemove]; !ok {
		return errors.New("User not found in access tree")
	}
	children, _ := tree[toRemove]
	delete(tree, toRemove)
	for _, username := range children { //what happens when this is empty?
		e:=treeRemoveHelper(tree, username)
		if e != nil{
			return errors.New("Problem in remove tree")
		}
	}
	//clean up if more than one person gave access to the revoked person
	//appenerntly unnecessary but what the hell
	/*
	for k_ v in : range t{
		for index, val := v{
			if val == toRemove{
				remove(v, index)
			}
		}
	}
	*/
	return
}