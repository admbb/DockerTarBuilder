package enrich

import "testing"

func TestV2FlyParseIncludesAndSkips(t *testing.T) {
	files := V2FlyList{"service": "# comment\ndomain:Example.com\nfull:api.example.com @a\ninclude:child\nkeyword:example\ninclude:child @attr\n", "child": "example.org\ndomain:example.com\nregexp:.*example\n"}
	rules, skipped, err := ParseV2FlyApplication(files, "service", "service", "revision")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 || skipped != 4 {
		t.Fatalf("rules=%v skipped=%d", rules, skipped)
	}
}
func TestV2FlyRejectsIncompleteOrCyclicLists(t *testing.T) {
	for _, f := range []V2FlyList{{"a": "include:b"}, {"a": "include:b", "b": "include:a"}} {
		if _, _, err := ParseV2FlyApplication(f, "a", "a", "rev"); err == nil {
			t.Fatal("accepted an incomplete or cyclic snapshot")
		}
	}
}
