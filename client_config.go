package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
)

type Config struct {
	Secure bool   `json:"secure"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Path   string `json:"path"`
	UUID   string `json:"uuid"`
	Key    string `json:"key"`
}

func getMD5Hash(data []byte) []byte {
	hash := md5.Sum(data)
	return hash[:]
}

// 正确的加密函数 - 模拟客户端decrypt的反向操作
func encrypt(data []byte, key []byte) ([]byte, error) {
	// 1. 计算原始数据的MD5哈希
	hash := getMD5Hash(data)

	// 2. 创建AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 3. 使用MD5哈希作为IV创建CTR模式
	stream := cipher.NewCTR(block, hash)

	// 4. 加密数据
	encBuffer := make([]byte, len(data))
	stream.XORKeyStream(encBuffer, data)

	// 5. 返回格式: [MD5哈希(16字节)] + [加密数据]
	return append(hash, encBuffer...), nil
}

func encryptAES(data []byte, key []byte) ([]byte, error) {
	hash := getMD5Hash(data)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, hash)
	encBuffer := make([]byte, len(data))
	stream.XORKeyStream(encBuffer, data)
	return append(hash, encBuffer...), nil
}

func createSaltBytes(salt string) []byte {
	saltBytes := []byte(salt)
	saltBytes = append(saltBytes, bytes.Repeat([]byte{25}, 24)...)
	return saltBytes[:24]
}

func main() {
	fmt.Println("========== 生成正确的ConfigBuffer ==========")

	// 配置参数
	clientUUID := "525f4bd1d5d6918db4a4ae03381cd84f"
	salt := "123456abcdef"

	// 1. 生成ClientKey
	saltBytes := createSaltBytes(salt)
	uuidBytes, _ := hex.DecodeString(clientUUID)
	clientKey, _ := encryptAES(uuidBytes, saltBytes)

	// 2. 构建配置
	config := Config{
		Secure: false,
		Host:   "127.0.0.1",
		Port:   8001,
		Path:   "/",
		UUID:   clientUUID,
		Key:    hex.EncodeToString(clientKey),
	}

	configJSON, _ := json.Marshal(config)
	fmt.Printf("配置JSON: %s\n", string(configJSON))

	// 3. 使用clientKey的前16字节作为AES密钥加密配置
	aesKey := clientKey[:16]
	encryptedConfig, err := encrypt(configJSON, aesKey)
	if err != nil {
		fmt.Printf("加密失败: %v\n", err)
		return
	}

	// 4. 构建ConfigBuffer
	// 格式: [2字节长度] + [16字节AES Key] + [加密配置数据]
	totalDataLen := 16 + len(encryptedConfig)

	lenBytes := big.NewInt(int64(totalDataLen)).Bytes()
	if len(lenBytes) == 1 {
		lenBytes = append([]byte{0}, lenBytes...)
	}

	var configBuffer bytes.Buffer
	configBuffer.Write(lenBytes)
	configBuffer.Write(aesKey)
	configBuffer.Write(encryptedConfig)

	fmt.Printf("ConfigBuffer长度: %d\n", configBuffer.Len())

	// 输出
	fmt.Println("\n修正的ConfigBuffer:")
	fmt.Printf("var ConfigBuffer = \"")
	for _, b := range configBuffer.Bytes() {
		fmt.Printf("\\x%02X", b)
	}
	fmt.Printf("\"\n")
}
