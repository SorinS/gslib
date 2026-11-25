// Go's regexp in the regex benchmark (bench.py): the same protocol as
// bench.goose. Go's \w, \d, \s and \b are ASCII.
package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// Seconds for the best of the runs of f, by bench.goose's rule.
func best(f func()) float64 {
	b, total, runs := 1e9, 0.0, 0
	for runs < 20 && !(runs >= 3 && total >= 0.5) && !(runs >= 1 && total >= 3.0) {
		// a run repeats f until it has taken 5 ms
		t0, reps, t := time.Now(), 0, 0.0
		for reps == 0 || t < 0.005 {
			f()
			reps++
			t = time.Since(t0).Seconds()
		}
		total += t
		if t/float64(reps) < b {
			b = t / float64(reps)
		}
		runs++
	}
	return b
}

var sink *regexp.Regexp

func main() {
	table, _ := os.ReadFile(os.Args[1])
	text, _ := os.ReadFile(os.Args[2])
	corpus := os.Args[3]
	only := ""
	if len(os.Args) > 4 {
		only = os.Args[4]
	}
	mb := float64(len(text)) / 1e6
	for _, line := range strings.Split(string(table), "\n") {
		if line == "" || line[0] == '#' {
			continue
		}
		f := strings.Split(line, "\t")
		name, kind, pattern := f[0], f[1], f[2]
		if only != "" && only != name {
			continue
		}
		k, c0 := 0, time.Now()
		for k < 1 || (time.Since(c0).Seconds() < 0.2 && k < 1000) {
			sink = regexp.MustCompile(pattern)
			k++
		}
		fmt.Printf("%s %s compile_us %g\n", name, corpus, time.Since(c0).Seconds()/float64(k)*1e6)
		re := regexp.MustCompile(pattern)
		n := 0
		t := best(func() { n = len(re.FindAllIndex(text, -1)) })
		fmt.Printf("%s %s count %d\n", name, corpus, n)
		fmt.Printf("%s %s count_mbps %g\n", name, corpus, mb/t)
		if kind == "caps" {
			sum := 0
			t := best(func() {
				sum = 0
				for _, m := range re.FindAllSubmatchIndex(text, -1) {
					if m[2] >= 0 {
						sum += m[3] - m[2]
					}
				}
			})
			fmt.Printf("%s %s caps_sum %d\n", name, corpus, sum)
			fmt.Printf("%s %s caps_mbps %g\n", name, corpus, mb/t)
		}
	}
}
