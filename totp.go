package main

// #cgo LDFLAGS: -framework CoreFoundation -framework Security
//
// #include <CoreFoundation/CoreFoundation.h>
// #include <Security/Security.h>
import "C"

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
	"unsafe"
)


func FindPassword(serverName string) string {
	var cpasslen C.UInt32
	var cpassword unsafe.Pointer
	var itemRef C.SecKeychainItemRef

	// errCode := C.SecKeychainFindInternetPassword(
	// 	nil,
	// 	C.UInt32(len(serverName)), C.CString(serverName),
	// 	C.UInt32(0), C.CString(""),
	// 	C.UInt32(0), C.CString(""),
	// 	C.UInt32(0), C.CString(""),
	// 	C.UInt16(0),
	// 	C.kSecProtocolTypeAny,
	// 	C.kSecProtocolTypeAny,
	// 	&cpasslen, &cpassword,
	// 	&itemRef,
	// )

	errCode := C.SecKeychainFindGenericPassword(
		nil,
		C.UInt32(len(serverName)), C.CString(serverName),
		C.UInt32(0), C.CString(""),
		&cpasslen, &cpassword,
		&itemRef,
	)

	if errCode != C.noErr {
		return ""
	}
	defer C.CFRelease(C.CFTypeRef(itemRef))
	defer C.SecKeychainItemFreeContent(nil, cpassword)

	buf := C.GoBytes(cpassword, C.int(cpasslen))
	return string(buf)
}

func Totp(secret string) string {
	key, _ := base32.StdEncoding.DecodeString(strings.ToUpper(secret))
	hash := hmac.New(sha1.New, key)
	t := new(bytes.Buffer)
	binary.Write(t, binary.BigEndian, time.Now().Unix()/30)
	hash.Write(t.Bytes())

	h := hash.Sum(nil)
	o := h[len(h)-1] & 0xf
	c := int32(h[o]&0x7f)<<24 | int32(h[o+1])<<16 | int32(h[o+2])<<8 | int32(h[o+3])
	return fmt.Sprintf("%010d", c%100000000)[4:10]
}

func main() {
	pathname := os.Args[1]
    var term = flag.Int("term", "\n", "string terminal character")
    
	fmt.Println("ip has value ", *ip)
    
    
	if len(pathname) == 0 {
		return
	}
	secret := FindPassword("otpauth://totp/" + pathname)

	if len(secret) == 0 {
		return
	}

	totp := Totp(secret)
    
    if term == "\n" {
       fmt.Println(totp)
    }
    fmt.Printf("%s%s", totp, term)
}
