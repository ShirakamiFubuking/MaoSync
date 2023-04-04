package main

import (
	"archive/tar"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	ipfs "github.com/ipfs/go-ipfs-api"
)

func encrypt(inputFloder, outputFile string, publicKeyRing, signKeyRing *crypto.KeyRing) error {
	f, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer f.Close()
	encryptWriter, err := publicKeyRing.EncryptStreamWithCompression(f, nil, signKeyRing)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(encryptWriter)
	root := inputFloder
	err = filepath.Walk(root, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if root == path {
			return nil
		}

		h, _ := tar.FileInfoHeader(info, "")
		h.Name = strings.TrimPrefix(path, root+SEPARATOR)
		h.Name = strings.ReplaceAll(h.Name, SEPARATOR, "/")

		fmt.Println(h.Name)
		tw.WriteHeader(h)

		if !info.IsDir() {
			tmp, err := os.Open(path)
			if err != nil {
				return err
			}
			io.Copy(tw, tmp)
			tmp.Close()
		}
		return nil
	})
	if err != nil {
		return err
	}
	err = tw.Close()
	if err != nil {
		return err
	}
	return encryptWriter.Close()
}

func decrypt(file, target string, privateKeyRing, verifyKeyRing *crypto.KeyRing) error {
	f, err := os.Stat(target)
	if os.IsExist(err) && !f.IsDir() {
		return err
	} else if os.IsNotExist(err) {
		os.Mkdir(target, os.ModeDir)
	}
	fsrc, err := os.Open(file)
	if err != nil {
		return err
	}
	defer fsrc.Close()
	decryptReader, err := privateKeyRing.DecryptStream(fsrc, verifyKeyRing, crypto.GetUnixTime())
	tr := tar.NewReader(decryptReader)
	root := target + SEPARATOR
	for hdr, err := tr.Next(); err != io.EOF; hdr, err = tr.Next() {
		if err != nil {
			return err
		}
		fi := hdr.FileInfo()
		// hdr.Name has the full path, FileInfo.Name() only return base name
		fname := strings.ReplaceAll(hdr.Name, "/", `\`) // windows
		if fi.IsDir() {
			err := os.Mkdir(root+fname, os.ModeDir)
			if err != nil && !strings.Contains(err.Error(), "file already exists") {
				return err
			}
			os.Chmod(fname, fi.Mode().Perm())
			continue
		}
		fw, err := os.Create(root + fname)
		if err != nil {
			return err
		}

		n, err := io.Copy(fw, tr)
		if err != nil {
			return err
		}
		fmt.Printf("%s, total %d bytes\n", fname, n)
		os.Chmod(fname, fi.Mode().Perm())

		fw.Close()
	}
	return err
}

const SEPARATOR = string(os.PathSeparator)
const HELP = `ggg`
const PUBLIC_GATEWAY = "ipfs.io"

var WORKDIR string
var TEMPDIR string
var GATEWAY string = "127.0.0.1:5001"

var (
	// options
	addFile string
	getFile string
	keys    bool

	// keys
	privateKeyRing, publicKeyRing *crypto.KeyRing
	sh                            *ipfs.Shell
)

func init() {
	WORKDIR, _ = os.UserHomeDir()
	TEMPDIR = os.Getenv("TEMP")
	WORKDIR += SEPARATOR + ".maomao"
	flag.StringVar(&addFile, "addFile", "", "the file path which will add to IPFS")
	flag.StringVar(&getFile, "getFile", "", "the files CID")
	flag.BoolVar(&keys, "keys", false, "show your keys")

	// init work dir at userhome .maomao
	_, err := os.Stat(WORKDIR)
	// at first run, generate my key
	if os.IsNotExist(err) {
		fmt.Println("first run, generating key......")
		var name, email string
		fmt.Println("Please Enter name: ")
		fmt.Scanln(&name)
		fmt.Println("Please Enter email: ")
		fmt.Scanln(&email)
		os.Mkdir(WORKDIR, os.ModeDir)
		os.Mkdir(WORKDIR+SEPARATOR+"private key", os.ModeDir)
		os.Mkdir(WORKDIR+SEPARATOR+"public key", os.ModeDir)
		key, err := crypto.GenerateKey(name, email, "x25519", 0)
		if err != nil {
			panic(err)
		}
		armor, err := key.Armor()
		if err != nil {
			panic(err)
		}
		f, err := os.Create(WORKDIR + SEPARATOR + "private key" + SEPARATOR + key.GetFingerprint() + ".asc")
		if err != nil {
			panic(err)
		}
		_, err = f.WriteString(armor)
		if err != nil {
			panic(err)
		}
		publicKey, err := key.GetArmoredPublicKey()
		if err != nil {
			panic(err)
		}
		fmt.Println("Now you can publish your public key: ")
		fmt.Println(publicKey)
		fmt.Println("Your private key is stored in " + WORKDIR + SEPARATOR + "private key")
		return
	}

	privateKeyRing, err = loadKeys(WORKDIR + SEPARATOR + "private key")
	if err != nil {
		panic(err)
	}
	publicKeyRing, err = loadKeys(WORKDIR + SEPARATOR + "public key")
	if err != nil {
		panic(err)
	}

	// add self key
	for _, k := range privateKeyRing.GetKeys() {
		publicKeyRing.AddKey(k)
	}

	// init ipfs shell
	sh = ipfs.NewShell(GATEWAY)
}

func loadKeys(keysDir string) (*crypto.KeyRing, error) {
	keyRing := &crypto.KeyRing{}
	// load key ring
	err := filepath.Walk(keysDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		k, err := crypto.NewKeyFromArmoredReader(f)
		if err != nil {
			return err
		}
		return keyRing.AddKey(k)
	})
	return keyRing, err
}

func main() {
	flag.Parse()
	if keys {
		fmt.Println("My Public keys:")
		for _, key := range privateKeyRing.GetKeys() {
			fmt.Println(key.GetEntity().PrimaryIdentity().Name, key.GetFingerprint())
			armor, err := key.GetArmoredPublicKey()
			if err != nil {
				panic(err)
			}
			fmt.Println(armor)
		}
		fmt.Println("Trusted Keys From others:")
		for _, key := range publicKeyRing.GetKeys() {
			fmt.Println(key.GetEntity().PrimaryIdentity().Name, key.GetFingerprint())
			armor, err := key.GetArmoredPublicKey()
			if err != nil {
				panic(err)
			}
			fmt.Println(armor)
		}
		return
	}

	if addFile != "" {
		if !sh.IsUp() {
			panic("check IPFS api " + GATEWAY + " failed")
		}
		fmt.Printf("check IPFS api ok")
		fmt.Printf("encrypt file(folder) %s and add to IPFS\n", addFile)
		fmt.Println("using public key(who can decrypt):")
		for i, k := range publicKeyRing.GetKeys() {
			fmt.Printf("%d.%s\nFingerprint:%s", i+1, k.GetEntity().PrimaryIdentity().Name, k.GetFingerprint())
		}
		tmp := TEMPDIR + SEPARATOR + strconv.FormatInt(time.Now().UnixNano(), 16) + ".tar"
		encrypt(addFile, tmp, publicKeyRing, privateKeyRing)
		// add to IPFS
		f, err := os.Open(tmp)
		if err != nil {
			panic(err)
		}
		defer func() {
			f.Close()
			os.Remove(tmp)
		}()
		result, err := sh.Add(f)
		if err != nil {
			panic(err)
		}
		fmt.Println(result)
		return
	} else if getFile != "" {
		if !sh.IsUp() {
			fmt.Println("check IPFS api " + GATEWAY + " failed, use " + PUBLIC_GATEWAY)
			sh = ipfs.NewShell(PUBLIC_GATEWAY)
		}
		err := sh.Get(getFile, TEMPDIR)
		if err != nil {
			panic(err)
		}
		defer os.Remove(TEMPDIR + SEPARATOR + getFile)
		err = decrypt(TEMPDIR+SEPARATOR+getFile, "."+SEPARATOR+getFile, privateKeyRing, publicKeyRing)
		if err != nil {
			panic(err)
		}
	} else {
		flag.Usage()
	}
}
