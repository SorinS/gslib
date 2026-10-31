// gooracle runs Go's standard library on the inputs the compress package's
// tests and differentials give it, and prints what Go makes of them, so
// that the Goose side can be compared with Go's own behaviour.
//
//	gooracle [-version] <command> [flags] [args]
//
// Each command lives in a file of its own and registers itself in
// commands; `gooracle help` lists them.
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
)

const version = "1"

type command struct {
	usage string
	run   func(args []string) error
}

var commands = map[string]command{}

func register(name, usage string, run func(args []string) error) {
	if _, dup := commands[name]; dup {
		panic("gooracle: command registered twice: " + name)
	}
	commands[name] = command{usage, run}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: gooracle [-version] <command> [flags] [args]\ncommands:")
	names := make([]string, 0, len(commands))
	for n := range commands {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(os.Stderr, "  %-12s %s\n", n, commands[n].usage)
	}
}

func main() {
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Usage = usage
	flag.Parse()
	if *showVersion {
		fmt.Println("gooracle", version)
		return
	}
	if flag.NArg() < 1 {
		usage()
		os.Exit(2)
	}
	c, ok := commands[flag.Arg(0)]
	if !ok {
		fmt.Fprintf(os.Stderr, "gooracle: unknown command %q\n", flag.Arg(0))
		usage()
		os.Exit(2)
	}
	if err := c.run(flag.Args()[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "gooracle:", err)
		os.Exit(1)
	}
}
