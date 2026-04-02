package main

import (
	"attack/attack"
	"attack/oracle"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const maxWorkers = 16
const invalidPaddingStatus = 400

var client = &http.Client{
	Timeout: 60 * time.Second,
}

func doPostRequest(url string, body any) (*http.Response, error) {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(
		"POST",
		url,
		bytes.NewBuffer(jsonBody),
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func encryptMessage(msg string) ([]byte, error) {
	type Body struct {
		Text string `json:"text"`
	}
	body := Body{Text: msg}

	resp, err := doPostRequest("http://localhost:3000/encrypt", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	type Response struct {
		Encrypted string `json:"encrypted"`
	}
	var respBody Response
	err = json.NewDecoder(resp.Body).Decode(&respBody)
	if err != nil {
		return nil, err
	}

	fmt.Printf("Ciphertext (b64): %s\n", respBody.Encrypted)

	ivAndCt, err := base64.StdEncoding.DecodeString(respBody.Encrypted)
	if err != nil {
		return nil, err
	}

	return ivAndCt, nil
}

func oracleFn(ivAndCt []byte) (bool, error) {
	b64 := base64.StdEncoding.EncodeToString(ivAndCt)

	type Body struct {
		Encrypted string `json:"encrypted"`
	}
	body := Body{Encrypted: b64}

	resp, err := doPostRequest("http://localhost:3000/oracle", body)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	_, err = io.Copy(io.Discard, resp.Body)
	if err != nil {
		return false, err
	}

	return resp.StatusCode != invalidPaddingStatus, nil
}

func main() {
	msg := fmt.Sprintf(
		"This is a very secret message. Current timestamp: %d",
		time.Now().Unix(),
	)
	fmt.Printf("Message: %q\n", msg)

	ivAndCt, err := encryptMessage(msg)
	if err != nil {
		fmt.Printf("[ERROR] %s\n", err)
		os.Exit(1)
	}

	orc := oracle.NewOracle(oracleFn)
	recovered, err := attack.Attack(orc, ivAndCt, maxWorkers)
	if err != nil {
		fmt.Printf("[ERROR] %s\n", err)
		os.Exit(1)
	}

	callsUsed := orc.GetCalls()

	fmt.Printf("Recovered: %q\n", string(recovered))
	fmt.Printf("Oracle calls used: %d\n", callsUsed)
}
