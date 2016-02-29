package main // import "github.com/jbarratt/sshduserlookup"

import (
	"log"
	"os"

	"github.com/hpcloud/tail"
)

func main() {
	logfile := os.Args[1]
	t, err := tail.TailFile(logfile, tail.Config{Follow: true})
	if err != nil {
		log.Fatalf("Error opening logfile: %s", err)
	}
	for line := range t.Lines {
		handleLine(line.Text)
	}
}
