package catalog

import (
	"netflow-plus-v2/internal/correlation"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCatalogUsesBundledBrandIconsAndSpecificDomains(t *testing.T) {
	apps, rules, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, app := range apps {
		if app.Icon == "" || !ValidIcon(app.Icon) {
			t.Errorf("application %s lacks an allowed bundled icon", app.ID)
			continue
		}
		if _, err := os.Stat(filepath.Join("..", "..", "web", "public", strings.TrimPrefix(app.Icon, "/"))); err != nil {
			t.Errorf("icon for %s: %v", app.ID, err)
		}
	}
	for domain, want := range map[string]string{
		"www.douyin.com": "douyin", "onedrive.live.com": "onedrive", "www.microsoft.com": "microsoft",
		"api.openai.com": "openai_api", "openai.com": "openai", "chatgpt.com": "chatgpt",
		"cloud.tencent.com": "tencentcloud", "item.jd.com": "jingdong",
		"www.yangkeduo.com": "pinduoduo", "www.xunlei.com": "xunlei",
		"login.live.com": "", "www.qq.com": "",
	} {
		if got, _ := correlation.MatchDomain(rules, domain); got != want {
			t.Errorf("%s matched %q, want %q", domain, got, want)
		}
	}
}
