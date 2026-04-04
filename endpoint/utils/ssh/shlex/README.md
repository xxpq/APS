# shlex

shlex is a library to make a lexical analyzer like Unix shell for
Go.


## Usage

```go
package main

func main() {
    cmd := `cp -Rdp "file name" 'file name2' dir\ name`
    words, err := shlex.Split(cmd, true)
    if err != nil {
        log.Fatal(err)
    }

    for _, w := range words {
        fmt.Println(w)
    }
}
```
output

    cp
    -Rdp
    file name
    file name2
    dir name