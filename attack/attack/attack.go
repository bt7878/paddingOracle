package attack

import (
	"attack/oracle"
	"bytes"
	"context"
	"crypto/aes"
	"fmt"
	"sync"

	"golang.org/x/sync/errgroup"
)

func pkcs7Unpad(data []byte) ([]byte, bool) {
	n := len(data)

	if n == 0 {
		return nil, false
	}

	pad := int(data[n-1])
	if pad == 0 || pad > aes.BlockSize {
		return nil, false
	}

	for i := n - pad; i < n; i++ {
		if data[i] != byte(pad) {
			return nil, false
		}
	}

	return data[:n-pad], true
}

func bruteForce(oracle *oracle.Oracle, ctBlock []byte, crafted []byte, j int, padByte byte, maxWorkers int) (int, error) {
	found := -1
	var once sync.Once

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(maxWorkers)

	for guess := 0; guess < 256; guess++ {
		if ctx.Err() != nil {
			break
		}

		guess := guess
		g.Go(func() error {
			select {
			case <-ctx.Done():
				return nil
			default:
			}

			probe := make([]byte, aes.BlockSize*2)
			copy(probe, crafted)
			probe[j] = byte(guess)
			copy(probe[aes.BlockSize:], ctBlock)

			valid, err := oracle.HasValidPadding(probe)
			if err != nil {
				return err
			}
			if !valid {
				return nil
			}

			if padByte == 1 && j > 0 {
				probe[j-1] ^= 0xFF
				valid, err := oracle.HasValidPadding(probe)
				if err != nil {
					return err
				}
				if !valid {
					return nil
				}
			}

			once.Do(func() {
				found = guess
				cancel()
			})

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return -1, err
	}

	return found, nil
}

func decryptBlock(oracle *oracle.Oracle, prevBlock, ctBlock []byte, maxWorkers int) ([]byte, error) {
	bs := aes.BlockSize
	intermediate := make([]byte, bs)
	recovered := make([]byte, bs)

	for j := bs - 1; j >= 0; j-- {
		padByte := byte(bs - j)

		crafted := make([]byte, bs)
		for k := j + 1; k < bs; k++ {
			crafted[k] = intermediate[k] ^ padByte
		}

		guess, err := bruteForce(oracle, ctBlock, crafted, j, padByte, maxWorkers)
		if err != nil {
			return nil, err
		}
		if guess < 0 {
			return nil, fmt.Errorf("no valid guess for byte %d", j)
		}
		fmt.Printf("Byte %d: guess %d\n", j, guess)

		intermediate[j] = byte(guess) ^ padByte
		recovered[j] = intermediate[j] ^ prevBlock[j]
	}

	return recovered, nil
}

func Attack(oracle *oracle.Oracle, ivAndCt []byte, maxWorkers int) ([]byte, error) {
	bs := aes.BlockSize
	numBlocks := len(ivAndCt)/bs - 1
	plainBlocks := make([][]byte, numBlocks)

	for i := 0; i < numBlocks; i++ {
		fmt.Printf("Starting block %d/%d\n", i+1, numBlocks)
		prevBlock := ivAndCt[i*bs : (i+1)*bs]
		ctBlock := ivAndCt[(i+1)*bs : (i+2)*bs]

		plainBlock, err := decryptBlock(oracle, prevBlock, ctBlock, maxWorkers)
		if err != nil {
			return nil, err
		}

		plainBlocks[i] = plainBlock
		fmt.Printf("Solved block %d: %x\n", i+1, string(plainBlocks[i]))
	}

	raw := bytes.Join(plainBlocks, nil)
	if unpadded, ok := pkcs7Unpad(raw); ok {
		return unpadded, nil
	}

	return raw, nil
}
