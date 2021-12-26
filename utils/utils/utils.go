package utils

import (
	"crypto/md5"
	"encoding/hex"
	"github.com/sirupsen/logrus"
	"os"
	"regexp"
)

func GetMD5Hash(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

func RemoveNonAlphaNumeric(source string) (string, error) {
	// Make a Regex to say we only want
	reg, err := regexp.Compile("[^a-zA-Z0-9]+")
	if err != nil {
		return "", err
	}
	processedString := reg.ReplaceAllString(source, "_")
	return processedString, nil
}

func DeleteFile(path string) {
	// delete file
	var err = os.Remove(path)
	if isError(err) {
		return
	}

	logrus.Infoln(" ==> done deleting file")
}
func isError(err error) bool {
	if err != nil {
		logrus.Errorln(err.Error())
	}

	return err != nil
}
