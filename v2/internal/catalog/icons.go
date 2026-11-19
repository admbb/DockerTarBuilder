package catalog

// Icons returns the paths that users can select from the bundled icon library.
func Icons() []string {
	return []string{
		"/icons/alibabacloud.svg", "/icons/apple.svg", "/icons/baidu.svg", "/icons/bilibili.svg",
		"/icons/deepseek.svg", "/icons/discord.svg", "/icons/docker.svg", "/icons/facebook.svg",
		"/icons/github.svg", "/icons/gitlab.svg", "/icons/gmail.svg", "/icons/google.svg",
		"/icons/icloud.svg", "/icons/instagram.svg", "/icons/neteasecloudmusic.svg", "/icons/netflix.svg",
		"/icons/npm.svg", "/icons/pypi.svg", "/icons/qq.svg", "/icons/spotify.svg", "/icons/steam.svg",
		"/icons/taobao.svg", "/icons/telegram.svg", "/icons/wechat.svg", "/icons/whatsapp.svg",
		"/icons/xiaohongshu.svg", "/icons/youtube.svg",
		"/icons/douyin.svg", "/icons/chatgpt.svg", "/icons/microsoft.svg", "/icons/onedrive.svg",
		"/icons/openai.svg", "/icons/tencentcloud.svg", "/icons/jingdong.svg", "/icons/pinduoduo.svg", "/icons/xunlei.svg",
	}
}

func ValidIcon(path string) bool {
	if path == "" {
		return true
	}
	for _, icon := range Icons() {
		if icon == path {
			return true
		}
	}
	return false
}
