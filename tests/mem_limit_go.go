package main

import (
  "context"
  "fmt"
  "os/signal"
  "runtime"
  "sync"
  "syscall"
  "time"
)

func main() {
  ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
  defer cancel()

  var wg sync.WaitGroup

  numCPU := runtime.NumCPU()
  runtime.GOMAXPROCS(numCPU)

  const memChunkMB = 1
  go func() {
    wg.Add(1)
    defer wg.Done()

    for ctx.Err() == nil {
      chunk := make([]byte, memChunkMB*1024*1024)
      for i := 0; i < len(chunk); i++ {
        chunk[i] = byte(i % 256)
      }
      fmt.Printf("Allocated %d MB of memory\n", memChunkMB)
      time.Sleep(10 * time.Millisecond)
    }
  }()

  <-ctx.Done()
  fmt.Println("Received termination signal. Initiating shutdown...")

  wg.Wait()
  fmt.Println("Shutdown complete.")
}