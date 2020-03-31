package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	"testing"
	"reflect"
	"github.com/cs161-staff/userlib"
	_ "encoding/json"
	_ "encoding/hex"
	_ "github.com/google/uuid"
	_ "strings"
	_"errors"
	_ "strconv"
)

func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}

func TestInit(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

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

	//testing same username
	_, samenameerror:= InitUser("alice", "fubar")
	if samenameerror == nil{
		t.Error("This should have thrown an error for users with the same username")
	}	
}

func TestGetUser(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Initialized user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
	u1, err1 := GetUser("alice", "fubar")
	if err1 != nil {
		t.Error("Failed to get user", err1)
		return
	}
	t.Log("Got user", u1)

	//testing wrong password
	_, passwordError := GetUser("alice", "foo")
	if passwordError == nil {
		t.Error("should have thrown error for wrong password", passwordError)
		return
	}
	//trying to find an user that doesnt exist
	_, getusererror := GetUser("john denero", "oski")
	if getusererror == nil{
		t.Error("Should have thrown an error for non existant user")
	}
}

//given test for basic functionality
func TestStorage(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

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
	
	//trying to load non-existant file
	_, fileerror := u.LoadFile("file420")
	if fileerror == nil{
		t.Error("Should have thrown a error for trying to access non-existant file")
		t.Log("access non-existant file")
	}
}

//loads a file that the owner owns
func TestLoadFileOwned(t *testing.T){
	clear()
	t.Log("Testing loading user owned files")
	//initialize user
	u, _ := InitUser("user", "123")
	content:= []byte("file test")
	u.StoreFile("test file", content)
	retrive, e := u.LoadFile("test file")
	if e != nil{
		t.Error("failed download")
		return
	}
	if !reflect.DeepEqual(content, retrive){
		t.Error("file is diffrent")
		return
	}
}

//attempts to share a file that the user doesn't have
func TestShareFileNotFound(t *testing.T) {
	clear()
	u, _ := InitUser("alice", "fubar")
	_, _ = InitUser("bob", "foobar")
	_, err := u.ShareFile("filename", "bob")
	if err == nil {
		t.Error("An error should be thrown when the user attempts to share a file they do not have access to", err)
		return
	}
}

//attempts to share a file with a user that doesn't exist
func TestShareUserNotFound(t *testing.T) {
	clear()
	u, _ := InitUser("alice", "fubar")
	content:= []byte("file test")
	u.StoreFile("test file", content)
	_, err := u.ShareFile("filename", "bob")
	if err == nil {
		t.Error("An error should be thrown when the user attempts to share a file they do not have access to", err)
		return
	}
}

//attempts to load a file that the user doesn't have permission for or doesn't exist
func TestLoadFileNotFound(t *testing.T){
	clear()
	t.Log("Testing loading user owned files")
	//init user
	u, _ := InitUser("alice", "fubar")
	_, err := u.LoadFile("filename")
	if err == nil {
		t.Error("An error should be thrown when the user attempts to load a file they do not have access to", err)
		return
	}
}

func TestInvalidFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := u.LoadFile("this file does not exist")
	if err2 == nil {
		t.Error("Downloaded a ninexistent file", err2)
		return
	}
}

func TestRevokeNonExistantFile(t *testing.T){
	clear()
	u,_ := InitUser("oski", "bears")
	u2,_:= InitUser("chase", "garbers")
	_, shareError := u.ShareFile("not a file", u2.Username)
	if shareError == nil{
		t.Error("Should have thrown error for sharing a non existant file")
		return
	}
	
}

func TestRevokeNonExistantUser(t *testing.T){
	clear()
	u,_ := InitUser("oski", "bears")
	u.StoreFile("file1", []byte("test file "))
	_, shareError2 := u.ShareFile("file1", "non existant user")
	if shareError2 == nil{
		t.Error("Should have thrown error for sharing with non existant user")
		return
	}
}

func TestShare(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
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
	err = u2.ReceiveFile("file2", "alice", magic_string)
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
	//now lets revoke the file and try to access it again
	u.RevokeFile("file1", "bob")
	_, loadRevErr := u2.LoadFile("file2")
	if loadRevErr == nil {
		t.Error("Did not properly revoke access, user was still able to load file", loadRevErr)
		return
	}
}

func TestAppend(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

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
	//now test that appending works
	app := []byte("Did we pass")
	vApp := append(v, app...)
	appErr := u.AppendFile("file1", app)
	if appErr != nil {
		t.Error("There was an error whil appending the file", appErr)
		return
	}
	vApp2, appErr2 := u.LoadFile("file1")
	if appErr2 != nil {
		t.Error("Failed to upload and download the appended file", appErr2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Appended file is not the same", vApp, vApp2)
		return
	}
	//testing appending to unkown file
	appErr3 := u.AppendFile("file0", app)
	if appErr3 == nil{
		t.Error("Should have thrown error for appending to non-existant file")
	}
}

//attempts to revoke access from someone who is not a direct child of the owner
func TestRevokeNotDirectChild(t *testing.T) {
	clear()
	u1, _ := InitUser("alice", "pw1")
	u2, _ := InitUser("bob", "pw2")
	u3, _ := InitUser("charlie", "pw3")
	u1.StoreFile("file1", []byte("this is the file"))
	accTok1, _ := u1.ShareFile("file1", "bob")
	_ = u2.ReceiveFile("file2", "alice", accTok1)
	accTok2, _ := u2.ShareFile("file2", "charlie")
	_ = u3.ReceiveFile("file3", "bob", accTok2)
	//now the test
	err := u1.RevokeFile("file1", "charlie")
	if err == nil {
		t.Error("Should not be able to revoke access fro a user that is not a direct child of the owner")
	}
}

//attempts to revoke access despite not owning the file
func TestRevokeNotOwner(t *testing.T) {
	clear()
	u1, _ := InitUser("alice", "pw1")
	u2, _ := InitUser("bob", "pw2")
	u3, _ := InitUser("charlie", "pw3")
	u1.StoreFile("file1", []byte("this is the file"))
	accTok1, _ := u1.ShareFile("file1", "bob")
	_ = u2.ReceiveFile("file2", "alice", accTok1)
	accTok2, _ := u2.ShareFile("file2", "charlie")
	_ = u3.ReceiveFile("file3", "bob", accTok2)
	//now the test
	err := u2.RevokeFile("file2", "charlie")
	if err == nil {
		t.Error("Should not be able to revoke access when you don't own the file")
	}
}

//tests having multiple instances of a user
/*func TestMultInst(t *testing.T) {
	clear()
	u1, _ := InitUser("alice", "fubar")
	u2, _ := GetUser("alice", "fubar")
	data1 := []byte("this is the file")
	u1.StoreFile("file1", data1)
	data2, err := u2.LoadFile("file1")
	if !reflect.DeepEqual(data1, data2) || err != nil {
		t.Error("Multiple instances of a single user does not work for storing and loading")
	}
	u3, _ := InitUser("bob", "foobar")
	u4, _ := GetUser("bob", "foobar")
	accTok, _ := u1.ShareFile("file1", u3.Username)
	u3.ReceiveFile("file2", "alice", accTok)
	data3, err := u4.LoadFile("file2")
	if !reflect.DeepEqual(data1, data3) || err != nil {
		t.Error("Multiple instances of a single user does not work for sharing/receiving")
	}
}*/ // Ah shit

//tests a bunch of stuff having to do with receiving
func TestReceiveStuff(t *testing.T) {
	clear()
	u1, _ := InitUser("alice", "fubar")
	u2, _ := InitUser("bob", "fubar")
	u1.StoreFile("file1", []byte("this is the file"))
	u2.StoreFile("file1", []byte("this is another file"))
	accTok, _ := u1.ShareFile("file1", "bob")
	//receive a file that you already have a name for
	recErr := u2.ReceiveFile("file1", "alice", accTok)
	if recErr == nil {
		t.Error("you should not be able to receive a file that you already have a name for")
	}
	//receive a file from a user that doesn't exist
	recErr2 := u2.ReceiveFile("ghostFile", "charlie", accTok)
	if recErr2 == nil {
		t.Error("you should not be able to receive a file from a user that doesn't exist")
	}
	//receive a file with the incorrect accessToken (or one not meant for you)
	u3, _ := InitUser("charlie", "barfoo")
	recErr3 := u3.ReceiveFile("file1", "alice", accTok)
	if recErr3 == nil {
		t.Error("you should not be able to receive a file that is not intended for you")
	}
}