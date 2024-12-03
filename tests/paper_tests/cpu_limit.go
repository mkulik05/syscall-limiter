package main

import (
  "context"
  "fmt"
  "os/signal"
  "runtime"
  "sync"
  "syscall"
  
)

func main() {
  ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
  defer cancel()

  var wg sync.WaitGroup

  numCPU := runtime.NumCPU()
  runtime.GOMAXPROCS(numCPU)

  for i := 0; i < numCPU; i++ {
    go func() {
      wg.Add(1)
      defer wg.Done()

      fmt.Println("Started a CPU hog")
      for ctx.Err() == nil { }
    }()
  }

  <-ctx.Done()
  fmt.Println("Received termination signal. Initiating shutdown...")

  wg.Wait()
  fmt.Println("Shutdown complete.")
}