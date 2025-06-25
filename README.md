# Go Implementation of Simhash Algorithm

## A golang translation of [1e0ng/simhash](https://github.com/1e0ng/simhash) written in python

Written for [we-go-wayback](https://github.com/suryanshu-09/we-go-wayback): a golang rewrite of [wayback-discover-diff](https://github.com/internetarchive/wayback-discover-diff).

<p align="center">
  <a href="https://github.com/suryanshu-09/simhash/tags"><img src="https://img.shields.io/github/v/tag/suryanshu-09/simhash.svg" alt="Latest Tag"></a>
  <a href="https://pkg.go.dev/github.com/suryanshu-09/simhash"><img src="https://godoc.org/github.com/golang/gddo?status.svg" alt="Go Docs"></a>
  <a href="https://github.com/suryanshu-09/simhash/actions"><img src="https://github.com/charmbracelet/vhs/workflows/build/badge.svg" alt="Build Status"></a>
</p>
### Installation

```
go get github.com/suryanshu-09/Simhash
```

### Usage

#### Find a Simhash

```
package main

import (
  "fmt"

  s "github.com/suryanshu-09/simhash"
)

func main(){
  features := []string{"abc", "def"}
  simhash := s.NewSimhash(features)

  fmt.Println(simhash)

  simhash2 := s.NewSimhash(features, s.WithF(128))

  distance := simhash.Distance(simhash2)

  fmt.Println(distance)

}
```

This is a Go port of the original [1e0ng/simhash](https://github.com/1e0ng/simhash) by [1e0ng](https://github.com/1e0ng), originally written in Python and licensed under the MIT License.
