package main

import (
	"attack/attack"
	"attack/oracle"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
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

func oracleFn(ivAndCt []byte) bool {
	b64 := base64.StdEncoding.EncodeToString(ivAndCt)

	type Body struct {
		Encrypted string `json:"encrypted"`
	}
	body := Body{Encrypted: b64}

	resp, err := doPostRequest("http://localhost:3000/oracle", body)
	if err != nil {
		log.Fatal(err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(resp.Body)

	return resp.StatusCode != invalidPaddingStatus
}

func main() {
	msg := fmt.Sprintf(
		"This is a very secret message. Current timestamp: %d",
		time.Now().Unix(),
	)
	log.Printf("Message: %q\n", msg)

	type Body struct {
		Text string `json:"text"`
	}
	body := Body{Text: msg}

	resp, err := doPostRequest("http://localhost:3000/encrypt", body)
	if err != nil {
		log.Fatal(err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(resp.Body)

	type Response struct {
		Encrypted string `json:"encrypted"`
	}
	var respBody Response
	err = json.NewDecoder(resp.Body).Decode(&respBody)
	if err != nil {
		log.Fatal(err)
	}

	ivAndCt, err := base64.StdEncoding.DecodeString(respBody.Encrypted)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Ciphertext (b64): %s\n", respBody.Encrypted)

	orc := oracle.NewOracle(oracleFn)
	recovered := attack.Attack(orc, ivAndCt, maxWorkers)
	callsUsed := orc.GetCalls()

	log.Printf("Recovered: %q\n", string(recovered))
	log.Printf("Oracle calls used: %d\n", callsUsed)
}
