package attack

import (
	"attack/oracle"
	"bytes"
	"context"
	"crypto/aes"
	"log"
	"sync"
)

type semaphore chan struct{}

func newSemaphore(n int) semaphore { return make(semaphore, n) }
func (s semaphore) Acquire()       { s <- struct{}{} }
func (s semaphore) Release()       { <-s }

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

func bruteForce(
	oracle *oracle.Oracle,
	sem semaphore,
	ctBlock []byte,
	crafted []byte,
	j int,
	padByte byte,
) int {
	type hit struct{ guess int }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hits := make(chan hit, 1)
	var wg sync.WaitGroup

loop:
	for guess := 0; guess < 256; guess++ {
		select {
		case <-ctx.Done():
			break loop
		default:
		}

		wg.Add(1)
		go func(g int) {
			defer wg.Done()

			sem.Acquire()
			defer sem.Release()

			select {
			case <-ctx.Done():
				return
			default:
			}

			probe := make([]byte, aes.BlockSize*2)
			copy(probe, crafted)
			probe[j] = byte(g)
			copy(probe[aes.BlockSize:], ctBlock)

			if !oracle.HasValidPadding(probe) {
				return
			}

			if padByte == 1 && j > 0 {
				verify := make([]byte, len(probe))
				copy(verify, probe)
				verify[j-1] ^= 0xFF
				if !oracle.HasValidPadding(verify) {
					return
				}
			}

			select {
			case hits <- hit{g}:
				cancel()
			default:
			}
		}(guess)
	}

	go func() {
		wg.Wait()
		close(hits)
	}()

	if h, ok := <-hits; ok {
		return h.guess
	}
	return -1
}

func decryptBlock(oracle *oracle.Oracle, sem semaphore, prevBlock, ctBlock []byte) []byte {
	bs := aes.BlockSize
	intermediate := make([]byte, bs)
	recovered := make([]byte, bs)

	for j := bs - 1; j >= 0; j-- {
		padByte := byte(bs - j)

		crafted := make([]byte, bs)
		for k := j + 1; k < bs; k++ {
			crafted[k] = intermediate[k] ^ padByte
		}

		guess := bruteForce(oracle, sem, ctBlock, crafted, j, padByte)
		if guess < 0 {
			log.Fatalf("no valid guess for byte %d", j)
		}
		log.Printf("Byte %d: guess %d\n", j, guess)

		intermediate[j] = byte(guess) ^ padByte
		recovered[j] = intermediate[j] ^ prevBlock[j]
	}

	return recovered
}

func Attack(oracle *oracle.Oracle, ivAndCt []byte, maxWorkers int) []byte {
	bs := aes.BlockSize
	numBlocks := len(ivAndCt)/bs - 1

	sem := newSemaphore(maxWorkers)
	plainBlocks := make([][]byte, numBlocks)

	for i := 0; i < numBlocks; i++ {
		log.Printf("Starting block %d/%d\n", i+1, numBlocks)
		prevBlock := ivAndCt[i*bs : (i+1)*bs]
		ctBlock := ivAndCt[(i+1)*bs : (i+2)*bs]
		plainBlocks[i] = decryptBlock(oracle, sem, prevBlock, ctBlock)
		log.Printf("Solved block %d: %x\n", i+1, string(plainBlocks[i]))
	}

	raw := bytes.Join(plainBlocks, nil)
	if unpadded, ok := pkcs7Unpad(raw); ok {
		return unpadded
	}
	return raw
}
