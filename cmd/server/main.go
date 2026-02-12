package main

import (
	"log"
	"net/http"
	"os"

	"github.com/zapthedingbat/webdav-server/internal/config"
	"github.com/zapthedingbat/webdav-server/internal/webdavfs"
	"golang.org/x/net/webdav"
)

func main() {
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "/config/config.yaml"
	}
	indexHTMLPath := os.Getenv("INDEX_HTML_PATH")
	if indexHTMLPath == "" {
		indexHTMLPath = "/config/index.html"
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	fs := webdavfs.NewVirtualFS(cfg)
	indexHTML := webdavfs.LoadIndexHTML(indexHTMLPath)
	h := &webdav.Handler{
		FileSystem: fs,
		LockSystem: webdav.NewMemLS(),
		Prefix:     "/",
	}
	handler := webdavfs.IndexHandler(cfg, indexHTML, webdavfs.Middleware(cfg, h))

	log.Printf("listening on %s", cfg.Server.Listen)
	if err := http.ListenAndServe(cfg.Server.Listen, handler); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
