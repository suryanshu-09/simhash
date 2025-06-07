# Go Implementation of Simhash Algorithm

## A golang translation of [1e0ng/simhash](https://github.com/1e0ng/simhash) written in python

Written for [we-go-wayback](https://github.com/suryanshu-09/we-go-wayback): a golang rewrite of [wayback-discover-diff](https://github.com/internetarchive/wayback-discover-diff).

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

Docs available @ [pkg.go.dev/github.com/suryanshu-09/simhash](https://pkg.go.dev/github.com/suryanshu-09/simhash)

This is a Go port of the original [1e0ng/simhash](https://github.com/1e0ng/simhash) by [1e0ng](https://github.com/1e0ng), originally written in Python and licensed under the MIT License.
